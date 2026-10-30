from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.application.ports import AdvisoryRecord, NvdSyncKind
from app.application.sync_nvd import NvdFeedSyncResult, SyncNvd
from app.domain.advisory import Advisory

NOW = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)


def record(number: int) -> AdvisoryRecord:
    modified = datetime(2026, 10, 29, tzinfo=UTC)
    return AdvisoryRecord(
        Advisory(f"CVE-2026-{number:05}", modified, modified, "Received", (), ()), b"{}"
    )


@dataclass
class ListedFeed:
    name: str
    last_modified: datetime
    items: list[AdvisoryRecord]

    def records(self) -> Iterator[AdvisoryRecord]:
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
    synced_at: datetime | None
    already_stored: int = 0
    batches: list[int] = field(default_factory=list)
    recorded: list[tuple[NvdSyncKind, datetime, datetime]] = field(default_factory=list)

    def nvd_synced_at(self) -> datetime | None:
        return self.synced_at

    def write_advisories(self, records: Sequence[AdvisoryRecord]) -> int:
        self.batches.append(len(records))
        return len(records) - self.already_stored

    def record_nvd_sync(self, kind: NvdSyncKind, released: datetime, synced_at: datetime) -> None:
        self.recorded.append((kind, released, synced_at))


def source() -> ListedSource:
    return ListedSource(
        yearly=[
            ListedFeed("2002", datetime(2026, 10, 29, 7, tzinfo=UTC), [record(1)]),
            ListedFeed("2003", datetime(2026, 10, 29, 8, tzinfo=UTC), [record(2), record(3)]),
        ],
        recent=ListedFeed("modified", datetime(2026, 10, 30, 5, tzinfo=UTC), [record(4)]),
    )


def run(source: ListedSource, store: CountingStore) -> tuple[list[NvdFeedSyncResult], SyncNvd]:
    reported: list[NvdFeedSyncResult] = []
    sync = SyncNvd(source, store, now=lambda: NOW, on_feed=reported.append)
    return reported, sync


@pytest.mark.parametrize("synced_at", [None, NOW - timedelta(days=7, seconds=1)])
def test_all_feeds_are_read_when_never_synced_or_synced_over_seven_days_ago(
    synced_at: datetime | None,
) -> None:
    feeds = source()
    store = CountingStore(synced_at)
    reported, sync = run(feeds, store)

    result = sync.run()

    assert feeds.asked == ["all"]
    assert result.kind is NvdSyncKind.ALL
    assert reported == [NvdFeedSyncResult("2002", 1, 1), NvdFeedSyncResult("2003", 2, 2)]
    assert store.recorded == [(NvdSyncKind.ALL, datetime(2026, 10, 29, 8, tzinfo=UTC), NOW)]


def test_only_recent_changes_are_read_within_seven_days_of_the_last_sync() -> None:
    feeds = source()
    store = CountingStore(NOW - timedelta(days=7))
    reported, sync = run(feeds, store)

    result = sync.run()

    assert feeds.asked == ["recent"]
    assert result.kind is NvdSyncKind.RECENT_CHANGES
    assert reported == [NvdFeedSyncResult("modified", 1, 1)]
    assert store.recorded == [
        (NvdSyncKind.RECENT_CHANGES, datetime(2026, 10, 30, 5, tzinfo=UTC), NOW)
    ]


def test_records_are_written_in_batches_and_unchanged_ones_are_not_counted() -> None:
    feeds = source()
    feeds.recent.items = [record(number) for number in range(2_500)]
    store = CountingStore(NOW - timedelta(days=1), already_stored=100)
    reported, sync = run(feeds, store)

    sync.run()

    assert store.batches == [1_000, 1_000, 500]
    assert reported == [NvdFeedSyncResult("modified", 2_500, 2_200)]
