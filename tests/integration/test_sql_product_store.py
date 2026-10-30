from datetime import UTC, datetime

from sqlalchemy import Engine

from app.application.ports import AdvisoryRecord
from app.domain.advisory import Advisory, CnaRange, NvdRange
from app.domain.product import IndexedName, NameKey, Product, ProductRole, RegisteredProduct
from app.infrastructure.db.advisory_store import SqlAdvisoryStore
from app.infrastructure.db.product_store import SqlProductLedger, SqlProductNameIndex

MONDAY = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
FORTIOS = NameKey("fortinet", "fortios")
FORTIPROXY = NameKey("fortinet", "fortiproxy")


def nvd_range(vendor: str, product: str) -> NvdRange:
    return NvdRange(vendor, product, "*", None, None, None, "7.0.14", False)


def cna_range(vendor: str | None, product: str | None) -> CnaRange:
    return CnaRange(vendor, product, None, "unaffected", "7.0.0", "affected", None, "7.0.13", None)


def record(cve_id: str, nvd: tuple[NvdRange, ...], cna: tuple[CnaRange, ...]) -> AdvisoryRecord:
    return AdvisoryRecord(Advisory(cve_id, MONDAY, MONDAY, "Analyzed", nvd, cna), b"{}")


def indexed(engine: Engine) -> SqlProductNameIndex:
    store = SqlAdvisoryStore(engine)
    store.write_advisories(
        [
            record(
                "CVE-1", (nvd_range("fortinet", "fortios"),), (cna_range("Fortinet", "FortiOS"),)
            ),
            record("CVE-2", (nvd_range("fortinet", "fortios"),), ()),
            record(
                "CVE-3", (nvd_range("fortinet", "fortiproxy"),), (cna_range(None, "FortiProxy"),)
            ),
        ]
    )
    store.rebuild_product_names()
    return SqlProductNameIndex(engine)


def test_the_index_groups_spellings_under_one_key_and_counts_cves(engine: Engine) -> None:
    names = indexed(engine).search("forti", limit=10)

    assert names == [
        IndexedName(FORTIOS, ("fortinet fortios", "Fortinet FortiOS"), 3),
        IndexedName(FORTIPROXY, ("fortinet fortiproxy",), 1),
    ]


def test_a_query_can_span_the_vendor_and_the_product(engine: Engine) -> None:
    assert [name.key for name in indexed(engine).search("fortinetfortipro", limit=10)] == [
        FORTIPROXY
    ]


def test_counts_are_only_returned_for_keys_in_the_index(engine: Engine) -> None:
    counts = indexed(engine).cve_counts([FORTIOS, NameKey("fortinet", "fortigate")])

    assert counts == {FORTIOS: 3}


def test_the_ledger_keeps_products_per_company(engine: Engine) -> None:
    ledger = SqlProductLedger(engine)
    fortigate = Product(
        "山田製作所",
        "本社の FortiGate",
        (FORTIOS, FORTIPROXY),
        "7.0.12",
        ProductRole.VPN,
        "まちの電気屋",
    )
    other = Product("佐藤工業", "工場の FortiGate", (FORTIOS,), None, ProductRole.FACTORY, None)

    first = ledger.add(fortigate, registered_at=MONDAY)
    ledger.add(other, registered_at=MONDAY)

    assert ledger.products("山田製作所") == [RegisteredProduct(first, fortigate, MONDAY)]
    assert ledger.products("鈴木商店") == []
