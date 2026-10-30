from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from itertools import batched

from app.application.ports import AdvisoryStore, NvdFeedSource, NvdSyncKind

ALL_FEEDS_AFTER = timedelta(days=7)
WRITE_BATCH = 1_000


@dataclass(frozen=True)
class NvdFeedSyncResult:
    name: str
    read: int
    written: int


@dataclass(frozen=True)
class NvdSyncResult:
    kind: NvdSyncKind
    feeds: tuple[NvdFeedSyncResult, ...]


class SyncNvd:
    def __init__(
        self,
        source: NvdFeedSource,
        store: AdvisoryStore,
        now: Callable[[], datetime],
        on_feed: Callable[[NvdFeedSyncResult], None],
    ) -> None:
        self._source = source
        self._store = store
        self._now = now
        self._on_feed = on_feed

    def run(self) -> NvdSyncResult:
        started = self._now()
        synced_at = self._store.nvd_synced_at()
        if synced_at is None or started - synced_at > ALL_FEEDS_AFTER:
            kind = NvdSyncKind.ALL
            feeds = self._source.all_feeds()
        else:
            kind = NvdSyncKind.RECENT_CHANGES
            feeds = iter([self._source.recent_changes()])
        results = []
        newest: datetime | None = None
        for feed in feeds:
            read = written = 0
            for batch in batched(feed.records(), WRITE_BATCH, strict=False):
                read += len(batch)
                written += self._store.write_advisories(batch)
            result = NvdFeedSyncResult(feed.name, read, written)
            self._on_feed(result)
            results.append(result)
            newest = feed.last_modified if newest is None else max(newest, feed.last_modified)
        if newest is not None:
            self._store.record_nvd_sync(kind, released=newest, synced_at=started)
        return NvdSyncResult(kind, tuple(results))
