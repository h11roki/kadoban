import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

NOT_IN_A_KEY = re.compile(r"[^0-9a-z぀-ヿ一-鿿]")
KEY_WORD = re.compile(r"[0-9a-z぀-ヿ一-鿿]+")
NOT_ASCII = re.compile(r"[^0-9a-z]")
LEGAL_FORMS = frozenset(
    {"inc", "incorporated", "corp", "corporation", "co", "company", "ltd", "limited", "llc"}
    | {"plc", "gmbh", "ag", "sa", "kk", "株式会社", "有限会社"}
)


def name_key(text: str) -> str:
    return NOT_IN_A_KEY.sub("", unicodedata.normalize("NFKC", text).casefold())


def vendor_key(text: str) -> str:
    words = KEY_WORD.findall(unicodedata.normalize("NFKC", text).casefold())
    while len(words) > 1 and words[-1] in LEGAL_FORMS:
        words.pop()
    while len(words) > 1 and words[0] in LEGAL_FORMS:
        words.pop(0)
    return "".join(words)


def ascii_part(key: str) -> str:
    return NOT_ASCII.sub("", key)


@dataclass(frozen=True, order=True)
class NameKey:
    vendor: str
    product: str

    def __post_init__(self) -> None:
        if not self.vendor or not self.product:
            raise ValueError("名前の鍵のベンダーと製品は空にできない")
        if vendor_key(self.vendor) != self.vendor or name_key(self.product) != self.product:
            raise ValueError(f"名前の鍵は正規化した形で書く: {self.vendor}/{self.product}")

    @classmethod
    def parse(cls, text: str) -> "NameKey":
        vendor, slash, product = text.partition("/")
        if not slash:
            raise ValueError(f"名前の鍵は ベンダー/製品 の形で書く: {text!r}")
        return cls(vendor, product)

    def __str__(self) -> str:
        return f"{self.vendor}/{self.product}"


class ProductRole(StrEnum):
    VPN = "vpn"
    SERVER = "server"
    BUSINESS_SOFTWARE = "business_software"
    FACTORY = "factory"
    OTHER = "other"


@dataclass(frozen=True)
class Product:
    company: str
    label: str
    keys: tuple[NameKey, ...]
    version: str | None
    role: ProductRole
    maintainer: str | None

    def __post_init__(self) -> None:
        if not self.company.strip():
            raise ValueError("会社を書く")
        if not self.label.strip():
            raise ValueError("呼び名を書く")
        if not self.keys:
            raise ValueError("名前の鍵を 1 つ以上書く")
        if len(set(self.keys)) != len(self.keys):
            raise ValueError("同じ名前の鍵を 2 度書いている")


@dataclass(frozen=True)
class RegisteredProduct:
    id: int
    product: Product
    registered_at: datetime


@dataclass(frozen=True)
class Alias:
    name: str
    calls: tuple[str, ...]
    keys: tuple[NameKey, ...]

    def answers_to(self, query_key: str) -> bool:
        return any(
            query_key in call_key or call_key in query_key
            for call_key in (name_key(call) for call in self.calls)
            if call_key
        )


@dataclass(frozen=True)
class IndexedName:
    key: NameKey
    spellings: tuple[str, ...]
    cve_count: int
