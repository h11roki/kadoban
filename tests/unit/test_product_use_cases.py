from collections.abc import Collection
from datetime import UTC, datetime

import pytest

from app.application.list_products import ListProducts
from app.application.ports import InvalidRequest
from app.application.register_product import RegisterProduct
from app.application.search_products import ProductCandidate, SearchProducts
from app.domain.product import (
    Alias,
    IndexedName,
    NameKey,
    Product,
    ProductRole,
    RegisteredProduct,
)

NOW = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)
FORTIOS = NameKey("fortinet", "fortios")
FORTINET_FORTIOS = NameKey("fortinet", "fortinetfortios")
FORTIOS_CARRIER = NameKey("fortinet", "fortioscarrier")
FORTIPROXY = NameKey("fortinet", "fortiproxy")
CISCO_ASA = NameKey("cisco", "adaptivesecurityappliance")
UNKNOWN = NameKey("fortinet", "fortigate9999")


class ListedIndex:
    def __init__(self, names: list[IndexedName]) -> None:
        self.names = names

    def search(self, query_key: str, limit: int) -> list[IndexedName]:
        return [name for name in self.names if query_key in name.key.product][:limit]

    def cve_counts(self, keys: Collection[NameKey]) -> dict[NameKey, int]:
        return {name.key: name.cve_count for name in self.names if name.key in keys}

    def rebuild(self) -> None:
        raise NotImplementedError


class RecordingLedger:
    def __init__(self) -> None:
        self.added: list[tuple[Product, datetime]] = []

    def add(self, product: Product, registered_at: datetime) -> int:
        self.added.append((product, registered_at))
        return len(self.added)

    def products(self, company: str) -> list[RegisteredProduct]:
        return [
            RegisteredProduct(number, product, registered_at)
            for number, (product, registered_at) in enumerate(self.added, start=1)
            if product.company == company
        ]


INDEX = ListedIndex(
    [
        IndexedName(FORTIOS, ("nvd fortinet:fortios", "cna Fortinet:FortiOS"), 482),
        IndexedName(FORTINET_FORTIOS, ("cna Fortinet:Fortinet FortiOS",), 39),
        IndexedName(FORTIOS_CARRIER, ("nvd fortinet:fortios_carrier",), 12),
        IndexedName(FORTIPROXY, ("nvd fortinet:fortiproxy",), 248),
        IndexedName(CISCO_ASA, ("nvd cisco:adaptive_security_appliance",), 361),
    ]
)
FORTIGATE = Alias(
    "FortiGate(FortiOS)", ("FortiGate", "FortiOS"), (FORTIOS, FORTINET_FORTIOS, UNKNOWN)
)
ASA = Alias("Cisco ASA", ("ASA",), (CISCO_ASA,))


def search(call: str) -> list[ProductCandidate]:
    return SearchProducts(INDEX, [FORTIGATE]).run(call)


def test_an_alias_comes_first_with_only_the_keys_in_the_index_and_their_count() -> None:
    [first] = search("フォーティゲート FortiGate")

    assert first == ProductCandidate(
        "FortiGate(FortiOS)", (FORTIOS, FORTINET_FORTIOS), (), 521, from_alias=True
    )


def test_index_hits_follow_the_alias_without_repeating_its_keys() -> None:
    candidates = search("fortios")

    assert [(candidate.label, candidate.keys) for candidate in candidates] == [
        ("FortiGate(FortiOS)", (FORTIOS, FORTINET_FORTIOS)),
        ("nvd fortinet:fortios_carrier", (FORTIOS_CARRIER,)),
    ]


def test_a_short_alias_call_is_found_again_by_an_ascii_word_of_a_japanese_call() -> None:
    candidates = SearchProducts(INDEX, [ASA]).run("本社の ASA")

    assert [(candidate.label, candidate.from_alias) for candidate in candidates] == [
        ("Cisco ASA", True)
    ]


def test_a_call_with_nothing_to_search_for_is_refused() -> None:
    with pytest.raises(InvalidRequest, match="英数字"):
        search("—")


def product(*keys: NameKey) -> Product:
    return Product("山田製作所", "本社の FortiGate", keys, None, ProductRole.VPN, None)


def test_a_product_with_known_keys_is_added_to_the_ledger() -> None:
    ledger = RecordingLedger()

    product_id = RegisterProduct(INDEX, ledger, now=lambda: NOW).run(product(FORTIOS))

    assert (product_id, ledger.added) == (1, [(product(FORTIOS), NOW)])


def test_a_product_with_a_key_missing_from_the_index_is_refused() -> None:
    ledger = RecordingLedger()

    with pytest.raises(InvalidRequest, match="fortinet/fortigate9999"):
        RegisterProduct(INDEX, ledger, now=lambda: NOW).run(product(FORTIOS, UNKNOWN))

    assert ledger.added == []


def test_a_japanese_call_with_no_hits_is_searched_again_by_its_ascii_part() -> None:
    candidates = SearchProducts(INDEX, []).run("フォーティ fortiproxy")

    assert [candidate.keys for candidate in candidates] == [(FORTIPROXY,)]


def test_listing_finds_the_company_however_its_name_was_typed() -> None:
    ledger = RecordingLedger()
    ledger.add(
        Product("Acme 工業", "本社の FortiGate", (FORTIOS,), None, ProductRole.VPN, None), NOW
    )

    assert [entry.id for entry in ListProducts(ledger).run(" Ａｃｍｅ  工業 ")] == [1]


def test_a_japanese_call_is_searched_again_by_each_ascii_word_longest_first() -> None:
    candidates = SearchProducts(INDEX, []).run("ヤマハ fortiproxy の 2 台目")

    assert [candidate.keys for candidate in candidates] == [(FORTIPROXY,)]
