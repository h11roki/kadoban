from pathlib import Path

import pytest

from app.domain.product import NameKey, name_key
from app.infrastructure.aliases import TomlAliasBook


def test_the_alias_file_in_the_repository_loads_and_every_call_has_a_key() -> None:
    book = TomlAliasBook()

    fortigate = book.answering_to(name_key("FortiGate 60F"))

    assert [alias.name for alias in fortigate] == ["FortiGate(FortiOS)"]
    assert NameKey("fortinet", "fortios") in fortigate[0].keys
    assert book.answering_to(name_key("パルスセキュア"))[0].keys[0] == NameKey(
        "ivanti", "connectsecure"
    )


def test_an_alias_file_with_a_key_that_is_not_normalized_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "aliases.toml"
    path.write_text('[[alias]]\nname = "X"\ncalls = ["X"]\nkeys = ["Fortinet/FortiOS"]\n')

    with pytest.raises(ValueError, match="別名表"):
        TomlAliasBook(path)
