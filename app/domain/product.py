import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

KEY_CHARACTERS = r"0-9a-z\u3005\u3041-\u3096\u309d-\u309f\u30a1-\u30fa\u30fc-\u30ff\u4e00-\u9fff"
NOT_IN_A_KEY = re.compile(f"[^{KEY_CHARACTERS}]")
KEY_WORD = re.compile(f"[{KEY_CHARACTERS}]+")
SPACE_BEFORE_SOUND_MARK = re.compile(r"\s+(?=[\u3099\u309a])")
ASCII_WORD = re.compile(r"[0-9a-z]+")
SPACES = re.compile(r"\s+")
LEGAL_FORMS = frozenset(
    {"inc", "incorporated", "corp", "corporation", "co", "company", "ltd", "limited", "llc"}
    | {"plc", "gmbh", "ag", "sa", "kk"}
)
JAPANESE_LEGAL_FORMS = ("株式会社", "有限会社", "合同会社")
PLACEHOLDER_PRODUCTS = frozenset({"na", "unknown", "unspecified", "none", "notapplicable"})
PARTIAL_MATCH_LENGTH = 5
ASCII_WORD_LENGTH = 3


def _folded(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text).casefold()
    return unicodedata.normalize("NFKC", SPACE_BEFORE_SOUND_MARK.sub("", folded))


def name_key(text: str) -> str:
    return NOT_IN_A_KEY.sub("", _folded(text))


def vendor_key(text: str) -> str:
    words = KEY_WORD.findall(_folded(text))
    while len(words) > 1 and words[-1] in LEGAL_FORMS:
        words.pop()
    while len(words) > 1 and words[0] in LEGAL_FORMS:
        words.pop(0)
    key = "".join(words)
    stripped = None
    while stripped != key:
        stripped = key
        for form in JAPANESE_LEGAL_FORMS:
            if key.startswith(form) and len(key) > len(form):
                key = key.removeprefix(form)
            if key.endswith(form) and len(key) > len(form):
                key = key.removesuffix(form)
    return key


def ascii_words(text: str) -> list[str]:
    words = ASCII_WORD.findall(_folded(text))
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
        object.__setattr__(self, "version", (self.version or "").strip() or None)
        object.__setattr__(self, "maintainer", (self.maintainer or "").strip() or None)
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
        return any(
            call_key == query_key
            or (len(call_key) >= PARTIAL_MATCH_LENGTH and call_key in query_key)
            for call_key in (name_key(call) for call in self.calls)
            if call_key
        )


@dataclass(frozen=True)
class IndexedName:
    key: NameKey
    spellings: tuple[str, ...]
    cve_count: int


def index_key(vendor: str, product: str) -> NameKey | None:
    vendor_part, product_part = vendor_key(vendor), name_key(product)
    if not vendor_part or not product_part or product_part in PLACEHOLDER_PRODUCTS:
        return None
    return NameKey(vendor_part, product_part)
