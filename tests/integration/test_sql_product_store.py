from datetime import UTC, datetime

import pytest
from sqlalchemy import Engine, update

from app.application.ports import AdvisoryRecord, ReplicaError
from app.domain.advisory import Advisory, CnaRange, NvdRange
from app.domain.product import IndexedName, NameKey, Product, ProductRole, RegisteredProduct
from app.infrastructure.db.advisory_store import SqlAdvisoryStore
from app.infrastructure.db.product_store import SqlProductLedger, SqlProductNameIndex
from app.infrastructure.db.tables import product_spellings, products

MONDAY = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
FORTIOS = NameKey("fortinet", "fortios")
FORTIPROXY = NameKey("fortinet", "fortiproxy")


def nvd_range(vendor: str, product: str) -> NvdRange:
    return NvdRange(vendor, product, "*", None, None, None, "7.0.14", False)


def cna_range(vendor: str | None, product: str | None) -> CnaRange:
    return CnaRange(vendor, product, None, "unaffected", "7.0.0", "affected", None, "7.0.13", None)


def record(cve_id: str, nvd: tuple[NvdRange, ...], cna: tuple[CnaRange, ...]) -> AdvisoryRecord:
    return AdvisoryRecord(Advisory(cve_id, MONDAY, MONDAY, "Analyzed", nvd, cna), b"{}")


def indexed(engine: Engine, *records: AdvisoryRecord) -> SqlProductNameIndex:
    SqlAdvisoryStore(engine).write_advisories(records)
    index = SqlProductNameIndex(engine)
    index.rebuild()
    return index


def fortinet_index(engine: Engine) -> SqlProductNameIndex:
    return indexed(
        engine,
        record("CVE-1", (nvd_range("fortinet", "fortios"),), (cna_range("Fortinet", "FortiOS"),)),
        record("CVE-2", (nvd_range("fortinet", "fortios"),), ()),
        record("CVE-3", (nvd_range("fortinet", "fortiproxy"),), (cna_range(None, "FortiProxy"),)),
    )


def test_the_index_groups_spellings_under_one_key_and_counts_cves(engine: Engine) -> None:
    names = fortinet_index(engine).search("forti", limit=10)

    assert names == [
        IndexedName(FORTIOS, ("fortinet fortios", "Fortinet FortiOS"), 3),
        IndexedName(FORTIPROXY, ("fortinet fortiproxy",), 1),
    ]


def test_a_query_can_span_the_vendor_and_the_product(engine: Engine) -> None:
    assert [name.key for name in fortinet_index(engine).search("fortinetfortipro", limit=10)] == [
        FORTIPROXY
    ]


def test_counts_are_only_returned_for_keys_in_the_index(engine: Engine) -> None:
    counts = fortinet_index(engine).cve_counts([FORTIOS, NameKey("fortinet", "fortigate")])

    assert counts == {FORTIOS: 3}


def test_placeholder_product_names_are_left_out_of_the_index(engine: Engine) -> None:
    index = indexed(
        engine, record("CVE-9", (), (cna_range("n/a", "n/a"), cna_range("n/a", "Android")))
    )

    assert index.search("na", limit=10) == [
        IndexedName(NameKey("na", "android"), ("n/a Android",), 1)
    ]


def test_the_label_is_the_spelling_with_the_most_cves(engine: Engine) -> None:
    index = indexed(
        engine,
        record("CVE-1", (), (cna_range("Fortinet", "FortiOS"),)),
        record("CVE-2", (nvd_range("fortinet", "fortios"),), (cna_range("Fortinet", "FortiOS"),)),
    )

    [name] = index.search("fortios", limit=10)

    assert name.spellings == ("Fortinet FortiOS", "fortinet fortios")


def test_an_index_built_with_older_normalization_asks_for_a_rebuild(engine: Engine) -> None:
    index = fortinet_index(engine)
    with engine.begin() as connection:
        connection.execute(update(product_spellings).values(vendor_key="Fortinet"))

    with pytest.raises(ReplicaError, match="product reindex"):
        index.search("forti", limit=10)


def fortigate(company: str, *keys: NameKey) -> Product:
    return Product(company, "本社の FortiGate", keys, "7.0.12", ProductRole.VPN, "まちの電気屋")


def test_the_ledger_keeps_products_per_company_with_their_own_keys(engine: Engine) -> None:
    ledger = SqlProductLedger(engine)
    headquarters = fortigate("山田製作所", FORTIOS, FORTIPROXY)
    factory = Product(
        "山田製作所", "工場の FortiProxy", (FORTIPROXY,), None, ProductRole.FACTORY, None
    )

    first = ledger.add(headquarters, registered_at=MONDAY)
    ledger.add(fortigate("佐藤工業", FORTIOS), registered_at=MONDAY)
    third = ledger.add(factory, registered_at=MONDAY)

    assert ledger.products("山田製作所") == [
        RegisteredProduct(first, headquarters, MONDAY),
        RegisteredProduct(third, factory, MONDAY),
    ]
    assert ledger.products("鈴木商店") == []


def test_a_ledger_row_that_cannot_be_read_is_a_replica_error(engine: Engine) -> None:
    ledger = SqlProductLedger(engine)
    product_id = ledger.add(fortigate("山田製作所", FORTIOS), registered_at=MONDAY)
    with engine.begin() as connection:
        connection.execute(update(products).values(role="router"))

    with pytest.raises(ReplicaError, match=f"台帳の {product_id} 番が読めない"):
        ledger.products("山田製作所")
