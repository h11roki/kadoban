import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

NOT_IN_A_KEY = re.compile(r"[^0-9a-z぀-ヿ一-鿿]")
KEY_WORD = re.compile(r"[0-9a-z぀-ヿ一-鿿]+")
ASCII_WORD = re.compile(r"[0-9a-z]+")
SPACES = re.compile(r"\s+")
LEGAL_FORMS = frozenset(
    {"inc", "incorporated", "corp", "corporation", "co", "company", "ltd", "limited", "llc"}
    | {"plc", "gmbh", "ag", "sa", "kk", "株式会社", "有限会社"}
)
PLACEHOLDER_PRODUCTS = frozenset({"na", "unknown", "unspecified", "none", "notapplicable"})
PARTIAL_MATCH_LENGTH = 5
ASCII_WORD_LENGTH = 3


def name_key(text: str) -> str:
    return NOT_IN_A_KEY.sub("", unicodedata.normalize("NFKC", text).casefold())


def vendor_key(text: str) -> str:
    words = KEY_WORD.findall(unicodedata.normalize("NFKC", text).casefold())
    while len(words) > 1 and words[-1] in LEGAL_FORMS:
        words.pop()
    while len(words) > 1 and words[0] in LEGAL_FORMS:
        words.pop(0)
    return "".join(words)


def ascii_words(text: str) -> list[str]:
    words = ASCII_WORD.findall(unicodedata.normalize("NFKC", text).casefold())
    return sorted((word for word in words if len(word) >= ASCII_WORD_LENGTH), key=len, reverse=True)


def company_name(text: str) -> str:
    return SPACES.sub(" ", unicodedata.normalize("NFKC", text)).strip()


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
        object.__setattr__(self, "company", company_name(self.company))
        object.__setattr__(self, "label", self.label.strip())
        if not self.company:
            raise ValueError("会社を書く")
        if not self.label:
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
        for call_key in (name_key(call) for call in self.calls):
            shorter, longer = sorted((call_key, query_key), key=len)
            if shorter and (
                shorter == longer or (len(shorter) >= PARTIAL_MATCH_LENGTH and shorter in longer)
            ):
                return True
        return False


@dataclass(frozen=True)
class IndexedName:
    key: NameKey
    spellings: tuple[str, ...]
    cve_count: int
