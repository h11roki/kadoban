from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from app.domain.advisory import Advisory
from app.domain.exploited import ExploitedCatalog


class AdvisorySourceError(Exception):
    pass


class ReplicaError(Exception):
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
