from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.application.ports import (
    AdvisoryRecord,
    AdvisorySourceError,
    NvdSyncKind,
    UnreadableRecord,
)
from app.application.sync_nvd import NvdFeedSyncResult, SyncNvd
from app.domain.advisory import Advisory

NOW = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)
FEED_2002 = datetime(2026, 10, 29, 7, tzinfo=UTC)
FEED_2003 = datetime(2026, 10, 29, 8, tzinfo=UTC)
FEED_MODIFIED = datetime(2026, 10, 30, 5, tzinfo=UTC)


def record(number: int) -> AdvisoryRecord:
    modified = datetime(2026, 10, 29, tzinfo=UTC)
    return AdvisoryRecord(
        Advisory(f"CVE-2026-{number:05}", modified, modified, "Received", (), ()), b"{}"
    )


def unreadable(number: int) -> UnreadableRecord:
    return UnreadableRecord(f"CVE-2026-9{number:04}", None, "vulnStatus が無い")


@dataclass
class ListedFeed:
    name: str
    last_modified: datetime
    items: list[AdvisoryRecord | UnreadableRecord]

    def records(self) -> Iterator[AdvisoryRecord | UnreadableRecord]:
        return iter(self.items)


@dataclass
class ListedSource:
    yearly: list[ListedFeed]
    recent: ListedFeed
    asked: list[str] = field(default_factory=list)

    def all_feeds(self) -> Iterator[ListedFeed]:
        self.asked.append("all")
        return iter(self.yearly)

    def recent_changes(self) -> ListedFeed:
        self.asked.append("recent")
        return self.recent


@dataclass
class CountingStore:
    released_at: datetime | None
    already_stored: int = 0
    batches: list[int] = field(default_factory=list)
    unreadable: list[tuple[UnreadableRecord, datetime]] = field(default_factory=list)
    recorded: list[tuple[NvdSyncKind, datetime, datetime]] = field(default_factory=list)

    def nvd_released_at(self) -> datetime | None:
        return self.released_at

    def write_advisories(self, records: Sequence[AdvisoryRecord]) -> int:
        self.batches.append(len(records))
        return len(records) - self.already_stored

    def record_unreadable(self, records: Sequence[UnreadableRecord], seen_at: datetime) -> None:
        self.unreadable += [(record, seen_at) for record in records]

    def record_nvd_sync(self, kind: NvdSyncKind, released: datetime, synced_at: datetime) -> None:
        self.recorded.append((kind, released, synced_at))


def source() -> ListedSource:
    return ListedSource(
        yearly=[
            ListedFeed("2002", FEED_2002, [record(1)]),
            ListedFeed("2003", FEED_2003, [record(2), record(3)]),
        ],
        recent=ListedFeed("modified", FEED_MODIFIED, [record(4)]),
    )


def sync(feeds: ListedSource, store: CountingStore) -> tuple[SyncNvd, list[NvdFeedSyncResult]]:
    reported: list[NvdFeedSyncResult] = []
    return SyncNvd(feeds, store, now=lambda: NOW, on_feed=reported.append), reported


@pytest.mark.parametrize("released_at", [None, NOW - timedelta(days=7, seconds=1)])
def test_all_feeds_are_read_when_the_copy_is_missing_or_older_than_seven_days(
    released_at: datetime | None,
) -> None:
    feeds = source()
    store = CountingStore(released_at)
    sync_nvd, reported = sync(feeds, store)

    kind = sync_nvd.run()

    assert feeds.asked == ["all"]
    assert kind is NvdSyncKind.ALL
    assert reported == [
        NvdFeedSyncResult("2002", 1, 1, ()),
        NvdFeedSyncResult("2003", 2, 2, ()),
    ]


def test_a_full_sync_is_as_fresh_as_its_newest_feed() -> None:
    store = CountingStore(released_at=None)
    sync_nvd, _ = sync(source(), store)

    sync_nvd.run()

    assert store.recorded == [(NvdSyncKind.ALL, FEED_2003, NOW)]


def test_only_recent_changes_are_read_while_the_copy_is_within_seven_days() -> None:
    feeds = source()
    store = CountingStore(NOW - timedelta(days=7))
    sync_nvd, reported = sync(feeds, store)

    kind = sync_nvd.run()

    assert feeds.asked == ["recent"]
    assert kind is NvdSyncKind.RECENT_CHANGES
    assert reported == [NvdFeedSyncResult("modified", 1, 1, ())]
    assert store.recorded == [(NvdSyncKind.RECENT_CHANGES, FEED_MODIFIED, NOW)]


def test_records_are_written_in_batches_and_unchanged_ones_are_not_counted() -> None:
    feeds = source()
    feeds.recent.items = [record(number) for number in range(2_500)]
    store = CountingStore(NOW - timedelta(days=1), already_stored=100)
    sync_nvd, reported = sync(feeds, store)

    sync_nvd.run()

    assert store.batches == [500, 500, 500, 500, 500]
    assert reported == [NvdFeedSyncResult("modified", 2_500, 2_000, ())]


def test_unreadable_records_are_skipped_kept_in_the_store_and_reported() -> None:
    feeds = source()
    feeds.recent.items = [record(number) for number in range(200)] + [unreadable(1)]
    store = CountingStore(NOW - timedelta(days=1))
    sync_nvd, reported = sync(feeds, store)

    sync_nvd.run()

    assert store.batches == [200]
    assert store.unreadable == [(unreadable(1), NOW)]
    assert reported == [NvdFeedSyncResult("modified", 201, 200, (unreadable(1),))]
    assert len(store.recorded) == 1


def test_a_small_feed_tolerates_a_handful_of_unreadable_records() -> None:
    feeds = source()
    feeds.recent.items = [record(number) for number in range(296)] + [
        unreadable(number) for number in range(4)
    ]
    store = CountingStore(NOW - timedelta(days=1))
    sync_nvd, _ = sync(feeds, store)

    sync_nvd.run()

    assert len(store.recorded) == 1


def test_many_unreadable_records_mean_the_format_changed_and_the_sync_stops() -> None:
    feeds = source()
    feeds.recent.items = [record(number) for number in range(1_979)] + [
        unreadable(number) for number in range(21)
    ]
    store = CountingStore(NOW - timedelta(days=1))
    sync_nvd, _ = sync(feeds, store)

    with pytest.raises(AdvisorySourceError, match="21 / 2,000 件が読めず"):
        sync_nvd.run()

    assert store.recorded == []
