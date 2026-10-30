import tomllib
from pathlib import Path

from pydantic import BaseModel, ValidationError

from app.domain.product import Alias, NameKey

ALIASES_PATH = Path(__file__).with_name("product_aliases.toml")


class _AliasEntry(BaseModel):
    name: str
    calls: list[str]
    keys: list[str]


class _AliasFile(BaseModel):
    alias: list[_AliasEntry]


class TomlAliasBook:
    def __init__(self, path: Path = ALIASES_PATH) -> None:
        try:
            entries = _AliasFile.model_validate(tomllib.loads(path.read_text(encoding="utf-8")))
            self._aliases = tuple(
                Alias(entry.name, tuple(entry.calls), tuple(map(NameKey.parse, entry.keys)))
                for entry in entries.alias
            )
        except (OSError, tomllib.TOMLDecodeError, ValidationError, ValueError) as error:
            raise ValueError(f"別名表 {path} を読めない: {error}") from error

    def answering_to(self, query_key: str) -> list[Alias]:
        return [alias for alias in self._aliases if alias.answers_to(query_key)]
