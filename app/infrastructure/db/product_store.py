from collections.abc import Collection
from datetime import UTC, datetime

from sqlalchemy import Engine, func, insert, select, tuple_
from sqlalchemy.exc import DBAPIError

from app.application.ports import ReplicaError
from app.domain.product import IndexedName, NameKey, Product, ProductRole, RegisteredProduct
from app.infrastructure.db.engine import MIGRATION_HINT, TAKE_WRITE_LOCK
from app.infrastructure.db.tables import product_keys, product_spellings, products


class SqlProductNameIndex:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def search(self, query_key: str, limit: int) -> list[IndexedName]:
        names = product_spellings.c
        statement = (
            select(
                names.vendor_key, names.product_key, names.vendor, names.product, names.cve_count
            )
            .where((names.vendor_key + names.product_key).like(f"%{query_key}%"))
            .order_by(names.cve_count.desc(), names.vendor, names.product)
        )
        spellings: dict[tuple[str, str], dict[str, None]] = {}
        totals: dict[tuple[str, str], int] = {}
        try:
            with self._engine.connect() as connection:
                for vendor_key, product_key, vendor, product, cve_count in connection.execute(
                    statement
                ):
                    key = (vendor_key, product_key)
                    spellings.setdefault(key, {})[f"{vendor} {product}"] = None
                    totals[key] = totals.get(key, 0) + cve_count
        except DBAPIError as error:
            raise ReplicaError(f"手元の DB を読めない({error.orig})。{MIGRATION_HINT}") from error
        ranked = sorted(totals, key=lambda key: (-totals[key], key))[:limit]
        return [IndexedName(NameKey(*key), tuple(spellings[key]), totals[key]) for key in ranked]

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
        try:
            with self._engine.connect() as connection:
                return {
                    NameKey(vendor_key, product_key): cve_count
                    for vendor_key, product_key, cve_count in connection.execute(statement)
                }
        except DBAPIError as error:
            raise ReplicaError(f"手元の DB を読めない({error.orig})。{MIGRATION_HINT}") from error


class SqlProductLedger:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._writer = engine.execution_options(**{TAKE_WRITE_LOCK: True})

    def add(self, product: Product, registered_at: datetime) -> int:
        try:
            with self._writer.begin() as connection:
                product_id: int = connection.execute(
                    insert(products)
                    .values(
                        company=product.company,
                        label=product.label,
                        version=product.version,
                        role=product.role.value,
                        maintainer=product.maintainer,
                        registered_at=registered_at.astimezone(UTC).isoformat(
                            timespec="microseconds"
                        ),
                    )
                    .returning(products.c.id)
                ).scalar_one()
                connection.execute(
                    insert(product_keys),
                    [
                        {
                            "product_id": product_id,
                            "vendor_key": key.vendor,
                            "product_key": key.product,
                        }
                        for key in product.keys
                    ],
                )
                return product_id
        except DBAPIError as error:
            raise ReplicaError(f"手元の DB に書けない({error.orig})。{MIGRATION_HINT}") from error

    def products(self, company: str) -> list[RegisteredProduct]:
        try:
            with self._engine.connect() as connection:
                rows = connection.execute(
                    select(products).where(products.c.company == company).order_by(products.c.id)
                ).all()
                keys: dict[int, list[NameKey]] = {}
                for product_id, vendor_key, product_key in connection.execute(
                    select(
                        product_keys.c.product_id,
                        product_keys.c.vendor_key,
                        product_keys.c.product_key,
                    )
                    .where(product_keys.c.product_id.in_([row.id for row in rows]))
                    .order_by(product_keys.c.vendor_key, product_keys.c.product_key)
                ):
                    keys.setdefault(product_id, []).append(NameKey(vendor_key, product_key))
        except DBAPIError as error:
            raise ReplicaError(f"手元の DB を読めない({error.orig})。{MIGRATION_HINT}") from error
        return [
            RegisteredProduct(
                id=row.id,
                product=Product(
                    company=row.company,
                    label=row.label,
                    keys=tuple(keys.get(row.id, [])),
                    version=row.version,
                    role=ProductRole(row.role),
                    maintainer=row.maintainer,
                ),
                registered_at=datetime.fromisoformat(row.registered_at),
            )
            for row in rows
        ]
