import tomllib
from pathlib import Path

from pydantic import BaseModel

from app.application.ports import ConfigurationError
from app.domain.product import Alias, NameKey

ALIASES_PATH = Path(__file__).with_name("product_aliases.toml")


class _AliasEntry(BaseModel):
    name: str
    calls: list[str]
    keys: list[str]


class _AliasFile(BaseModel):
    alias: list[_AliasEntry]


def load_aliases(path: Path = ALIASES_PATH) -> tuple[Alias, ...]:
    try:
        entries = _AliasFile.model_validate(tomllib.loads(path.read_text(encoding="utf-8")))
        return tuple(
            Alias(entry.name, tuple(entry.calls), tuple(map(NameKey.parse, entry.keys)))
            for entry in entries.alias
        )
    except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
        raise ConfigurationError(f"別名表 {path} を読めない: {error}") from error
