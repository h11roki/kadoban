import pytest

from app.domain.product import (
    Alias,
    NameKey,
    Product,
    ProductRole,
    ascii_words,
    company_name,
    name_key,
    vendor_key,
)

FORTIOS = NameKey("fortinet", "fortios")


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("FortiOS", "fortios"),
        ("ＦｏｒｔｉＧａｔｅ　６０Ｆ", "fortigate60f"),
        ("Fortinet, Inc.", "fortinetinc"),
        ("mysql_connector/python", "mysqlconnectorpython"),
        ("ヤマハ RTX830", "ヤマハrtx830"),
        ("三菱電機 GX Works3", "三菱電機gxworks3"),
        ("—", ""),
    ],
)
def test_a_name_key_keeps_only_lowercase_letters_digits_kana_and_kanji(text: str, key: str) -> None:
    assert name_key(text) == key


def test_a_name_key_is_read_from_vendor_slash_product() -> None:
    assert NameKey.parse("fortinet/fortios") == FORTIOS
    assert str(FORTIOS) == "fortinet/fortios"


@pytest.mark.parametrize("text", ["fortios", "Fortinet/FortiOS", "fortinet/", "/fortios"])
def test_a_name_key_must_be_two_normalized_parts(text: str) -> None:
    with pytest.raises(ValueError, match="名前の鍵"):
        NameKey.parse(text)


@pytest.mark.parametrize(
    ("company", "label", "keys", "message"),
    [
        (" ", "本社の FortiGate", (FORTIOS,), "会社"),
        ("山田製作所", "", (FORTIOS,), "呼び名"),
        ("山田製作所", "本社の FortiGate", (), "1 つ以上"),
        ("山田製作所", "本社の FortiGate", (FORTIOS, FORTIOS), "2 度"),
    ],
)
def test_a_product_needs_a_company_a_label_and_distinct_keys(
    company: str, label: str, keys: tuple[NameKey, ...], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        Product(company, label, keys, "7.0.12", ProductRole.VPN, "まちの電気屋")


@pytest.mark.parametrize(
    ("query", "answers"),
    [
        ("fortigate", True),
        ("forti", True),
        ("fortigate60f", True),
        ("フォーティゲート", True),
        ("asa", False),
    ],
)
def test_an_alias_answers_to_a_query_inside_a_call_or_a_call_inside_the_query(
    query: str, answers: bool
) -> None:
    alias = Alias("FortiGate(FortiOS)", ("FortiGate", "フォーティゲート"), (FORTIOS,))

    assert alias.answers_to(query) is answers


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("Mitsubishi Electric Corporation", "mitsubishielectric"),
        ("Fortinet, Inc.", "fortinet"),
        ("SHARP Co., Ltd.", "sharp"),
        ("株式会社 日立製作所", "日立製作所"),
        ("Zinc", "zinc"),
        ("Inc", "inc"),
        ("fortinet", "fortinet"),
    ],
)
def test_a_vendor_key_drops_legal_forms_at_either_end(text: str, key: str) -> None:
    assert vendor_key(text) == key


@pytest.mark.parametrize(
    ("query", "answers"),
    [("asa", True), ("asahi", False), ("ciscoasa", True), ("os", False), ("cisco", True)],
)
def test_a_short_call_only_answers_to_the_same_word(query: str, answers: bool) -> None:
    alias = Alias("Cisco ASA", ("ASA", "Cisco ASA"), (NameKey("cisco", "asa"),))

    assert alias.answers_to(query) is answers


def test_ascii_words_are_the_longest_first_and_skip_short_ones() -> None:
    assert ascii_words("ヤマハ RTX830 の 2 台目と NVR510") == ["rtx830", "nvr510"]


def test_a_company_name_is_stored_in_one_spelling() -> None:
    product = Product(
        " Ａｃｍｅ  工業 ", "本社の FortiGate", (FORTIOS,), None, ProductRole.VPN, None
    )

    assert (product.company, company_name("Acme 工業")) == ("Acme 工業", "Acme 工業")
