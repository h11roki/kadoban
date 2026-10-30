from collections.abc import Collection
from datetime import datetime
from itertools import groupby
from operator import attrgetter

from sqlalchemy import Engine, delete, distinct, func, insert, select, tuple_

from app.application.ports import ReplicaError
from app.domain.product import (
    IndexedName,
    NameKey,
    Product,
    ProductRole,
    RegisteredProduct,
    index_key,
)
from app.infrastructure.db.engine import (
    CANNOT_READ,
    CANNOT_WRITE,
    TAKE_WRITE_LOCK,
    replica_errors,
    timestamp_text,
)
from app.infrastructure.db.tables import (
    cna_ranges,
    nvd_ranges,
    product_keys,
    product_spellings,
    products,
)


class SqlProductNameIndex:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._writer = engine.execution_options(**{TAKE_WRITE_LOCK: True})

    def search(self, query_key: str, limit: int) -> list[IndexedName]:
        names = product_spellings.c
        total = func.sum(names.cve_count).label("total")
        top = (
            select(names.vendor_key, names.product_key, total)
            .where((names.vendor_key + names.product_key).like(f"%{query_key}%"))
            .group_by(names.vendor_key, names.product_key)
            .order_by(total.desc(), names.vendor_key, names.product_key)
            .limit(limit)
        )
        with replica_errors(CANNOT_READ), self._engine.connect() as connection:
            totals = {
                (vendor_key, product_key): cve_count
                for vendor_key, product_key, cve_count in connection.execute(top)
            }
            spellings: dict[tuple[str, str], dict[str, None]] = {key: {} for key in totals}
            for vendor_key, product_key, vendor, product in connection.execute(
                select(names.vendor_key, names.product_key, names.vendor, names.product)
                .where(tuple_(names.vendor_key, names.product_key).in_(list(totals)))
                .order_by(names.cve_count.desc(), names.vendor, names.product)
            ):
                spellings[(vendor_key, product_key)][f"{vendor} {product}"] = None
        try:
            return [
                IndexedName(NameKey(*key), tuple(spellings[key]), cve_count)
                for key, cve_count in totals.items()
            ]
        except ValueError as error:
            raise ReplicaError(
                f"製品名の索引の鍵が今の正規化と合わない({error})。`product reindex` で作り直す"
            ) from error

    def cve_counts(self, keys: Collection[NameKey]) -> dict[NameKey, int]:
        if not keys:
            return {}
        names = product_spellings.c
        statement = (
            select(names.vendor_key, names.product_key, func.sum(names.cve_count))
            .where(
                tuple_(names.vendor_key, names.product_key).in_(
                    [(key.vendor, key.product) for key in keys]
                )
            )
            .group_by(names.vendor_key, names.product_key)
        )
        with replica_errors(CANNOT_READ), self._engine.connect() as connection:
            return {
                NameKey(vendor_key, product_key): cve_count
                for vendor_key, product_key, cve_count in connection.execute(statement)
            }

    def rebuild(self) -> None:
        rows: list[dict[str, str | int]] = []
        with replica_errors(CANNOT_READ), self._engine.connect() as connection:
            for source, table in (("nvd", nvd_ranges), ("cna", cna_ranges)):
                for vendor, product, cve_count in connection.execute(
                    select(table.c.vendor, table.c.product, func.count(distinct(table.c.cve_id)))
                    .where(table.c.vendor.is_not(None), table.c.product.is_not(None))
                    .group_by(table.c.vendor, table.c.product)
                ):
                    key = index_key(vendor, product)
                    if key is not None:
                        rows.append(
                            {
                                "source": source,
                                "vendor": vendor,
                                "product": product,
                                "vendor_key": key.vendor,
                                "product_key": key.product,
                                "cve_count": cve_count,
                            }
                        )
        with replica_errors(CANNOT_WRITE), self._writer.begin() as connection:
            connection.execute(delete(product_spellings))
            if rows:
                connection.execute(insert(product_spellings), rows)


class SqlProductLedger:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._writer = engine.execution_options(**{TAKE_WRITE_LOCK: True})

    def add(self, product: Product, registered_at: datetime) -> int:
        with replica_errors(CANNOT_WRITE), self._writer.begin() as connection:
            product_id: int = connection.execute(
                insert(products)
                .values(
                    company=product.company,
                    label=product.label,
                    version=product.version,
                    role=product.role.value,
                    maintainer=product.maintainer,
                    registered_at=timestamp_text(registered_at),
                )
                .returning(products.c.id)
            ).scalar_one()
            connection.execute(
                insert(product_keys),
                [
                    {"product_id": product_id, "vendor_key": key.vendor, "product_key": key.product}
                    for key in product.keys
                ],
            )
            return product_id

    def products(self, company: str) -> list[RegisteredProduct]:
        statement = (
            select(products, product_keys.c.vendor_key, product_keys.c.product_key)
            .join(product_keys)
            .where(products.c.company == company)
            .order_by(products.c.id, product_keys.c.vendor_key, product_keys.c.product_key)
        )
        with replica_errors(CANNOT_READ), self._engine.connect() as connection:
            rows = connection.execute(statement).all()
        registered: list[RegisteredProduct] = []
        for product_id, group in groupby(rows, key=attrgetter("id")):
            entries = list(group)
            first = entries[0]
            try:
                registered.append(
                    RegisteredProduct(
                        id=product_id,
                        product=Product(
                            company=first.company,
                            label=first.label,
                            keys=tuple(NameKey(row.vendor_key, row.product_key) for row in entries),
                            version=first.version,
                            role=ProductRole(first.role),
                            maintainer=first.maintainer,
                        ),
                        registered_at=datetime.fromisoformat(first.registered_at),
                    )
                )
            except ValueError as error:
                raise ReplicaError(
                    f"手元の DB の台帳の {product_id} 番が読めない: {error}"
                ) from error
        return registered
