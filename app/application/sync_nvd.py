from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from itertools import batched

from app.application.ports import (
    AdvisoryRecord,
    AdvisorySourceError,
    AdvisoryStore,
    NvdFeedSource,
    NvdSyncKind,
    UnreadableRecord,
)

ALL_FEEDS_AFTER = timedelta(days=7)
UNREADABLE_SHARE_LIMIT = 0.01
WRITE_BATCH = 1_000


@dataclass(frozen=True)
class NvdFeedSyncResult:
    name: str
    read: int
    written: int
    unreadable: tuple[UnreadableRecord, ...]


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
        released = self._store.nvd_released_at()
        if released is None or started - released > ALL_FEEDS_AFTER:
            kind = NvdSyncKind.ALL
            feeds = self._source.all_feeds()
        else:
            kind = NvdSyncKind.RECENT_CHANGES
            feeds = iter([self._source.recent_changes()])
        results = []
        covered: datetime | None = None
        for feed in feeds:
            read = written = 0
            unreadable: list[UnreadableRecord] = []
            for batch in batched(feed.records(), WRITE_BATCH, strict=False):
                read += len(batch)
                readable = [record for record in batch if isinstance(record, AdvisoryRecord)]
                unreadable += [record for record in batch if isinstance(record, UnreadableRecord)]
                if readable:
                    written += self._store.write_advisories(readable)
            if len(unreadable) > read * UNREADABLE_SHARE_LIMIT:
                raise AdvisorySourceError(
                    f"NVD の {feed.name} の {len(unreadable):,} / {read:,} 件が読めず、"
                    f"形が変わっているので止める。最初の理由: {unreadable[0].reason}"
                )
            result = NvdFeedSyncResult(feed.name, read, written, tuple(unreadable))
            self._on_feed(result)
            results.append(result)
            covered = feed.last_modified if covered is None else min(covered, feed.last_modified)
        if covered is not None:
            newest = covered if released is None else max(covered, released)
            self._store.record_nvd_sync(kind, released=newest, synced_at=started)
        return NvdSyncResult(kind, tuple(results))
