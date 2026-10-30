from collections.abc import Collection, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from app.domain.advisory import Advisory
from app.domain.exploited import ExploitedCatalog
from app.domain.product import Alias, IndexedName, NameKey, Product, RegisteredProduct


class AdvisorySourceError(Exception):
    pass


class ReplicaError(Exception):
    pass


class ConfigurationError(Exception):
    pass


class InvalidRequest(Exception):
    pass


class CatalogReplacement(StrEnum):
    REPLACED = "replaced"
    SAME_RELEASE = "same_release"
    OLDER_RELEASE = "older_release"


class NvdSyncKind(StrEnum):
    ALL = "all"
    RECENT_CHANGES = "recent_changes"


@dataclass(frozen=True)
class AdvisoryRecord:
    advisory: Advisory
    original_json: bytes


@dataclass(frozen=True)
class UnreadableRecord:
    cve_id: str | None
    last_modified: datetime | None
    reason: str


class ExploitedCatalogSource(Protocol):
    def fetch(self) -> ExploitedCatalog: ...


class ExploitedCatalogStore(Protocol):
    def replace_exploited_catalog_if_newer(
        self, catalog: ExploitedCatalog, synced_at: datetime
    ) -> CatalogReplacement: ...


class NvdFeed(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def last_modified(self) -> datetime: ...

    def records(self) -> Iterator[AdvisoryRecord | UnreadableRecord]: ...


class NvdFeedSource(Protocol):
    def all_feeds(self) -> Iterator[NvdFeed]: ...

    def recent_changes(self) -> NvdFeed: ...


class AdvisoryStore(Protocol):
    def nvd_released_at(self) -> datetime | None: ...

    def write_advisories(self, records: Sequence[AdvisoryRecord]) -> int: ...

    def record_unreadable(self, records: Sequence[UnreadableRecord], seen_at: datetime) -> None: ...

    def record_nvd_sync(
        self, kind: NvdSyncKind, released: datetime, synced_at: datetime
    ) -> None: ...

    def rebuild_product_names(self) -> None: ...


class ProductNameIndex(Protocol):
    def search(self, query_key: str, limit: int) -> list[IndexedName]: ...

    def cve_counts(self, keys: Collection[NameKey]) -> dict[NameKey, int]: ...


class AliasBook(Protocol):
    def answering_to(self, query_key: str) -> list[Alias]: ...


class ProductLedger(Protocol):
    def add(self, product: Product, registered_at: datetime) -> int: ...

    def products(self, company: str) -> list[RegisteredProduct]: ...
