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
UNREADABLE_COUNT_FLOOR = 20
WRITE_BATCH = 500


@dataclass(frozen=True)
class NvdFeedSyncResult:
    name: str
    read: int
    written: int
    unreadable: tuple[UnreadableRecord, ...]


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

    def run(self) -> NvdSyncKind:
        started = self._now()
        released = self._store.nvd_released_at()
        if released is None or started - released > ALL_FEEDS_AFTER:
            kind = NvdSyncKind.ALL
            feeds = self._source.all_feeds()
        else:
            kind = NvdSyncKind.RECENT_CHANGES
            feeds = iter([self._source.recent_changes()])
        newest: datetime | None = None
        written_in_all_feeds = 0
        try:
            for feed in feeds:
                read = written = 0
                unreadable: list[UnreadableRecord] = []
                for batch in batched(feed.records(), WRITE_BATCH, strict=False):
                    read += len(batch)
                    readable = [record for record in batch if isinstance(record, AdvisoryRecord)]
                    unreadable += [
                        record for record in batch if isinstance(record, UnreadableRecord)
                    ]
                    if readable:
                        written += self._store.write_advisories(readable)
                written_in_all_feeds += written
                if len(unreadable) > max(UNREADABLE_COUNT_FLOOR, read * UNREADABLE_SHARE_LIMIT):
                    raise AdvisorySourceError(
                        f"NVD の {feed.name} の {len(unreadable):,} / {read:,} 件が読めず、"
                        f"形が変わっているので止める。最初の理由: {unreadable[0].reason}"
                    )
                if unreadable:
                    self._store.record_unreadable(unreadable, seen_at=started)
                self._on_feed(NvdFeedSyncResult(feed.name, read, written, tuple(unreadable)))
                newest = feed.last_modified if newest is None else max(newest, feed.last_modified)
        finally:
            if written_in_all_feeds:
                self._store.rebuild_product_names()
        if newest is not None:
            self._store.record_nvd_sync(kind, released=newest, synced_at=started)
        return kind
