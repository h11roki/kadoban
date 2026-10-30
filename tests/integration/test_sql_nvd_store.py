import json
import zlib
from datetime import UTC, datetime

from sqlalchemy import Engine, select

from app.application.ports import AdvisoryRecord, NvdSyncKind, UnreadableRecord
from app.domain.advisory import Advisory, CnaRange, NvdRange
from app.infrastructure.db.advisory_store import SqlAdvisoryStore
from app.infrastructure.db.tables import (
    cna_ranges,
    cves,
    nvd_ranges,
    source_states,
    unreadable_cves,
)

PUBLISHED = datetime(2024, 2, 9, 9, 15, tzinfo=UTC)
MONDAY = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
TUESDAY = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)


def fortios_range(end_excluding: str) -> NvdRange:
    return NvdRange(
        vendor="fortinet",
        product="fortios",
        version="*",
        start_including="7.0.0",
        start_excluding=None,
        end_including=None,
        end_excluding=end_excluding,
        conditional=False,
    )


def record(cve_id: str, modified: datetime, end_excluding: str = "7.0.14") -> AdvisoryRecord:
    advisory = Advisory(
        cve_id=cve_id,
        published=PUBLISHED,
        last_modified=modified,
        status="Analyzed",
        nvd_ranges=(fortios_range(end_excluding),),
        cna_ranges=(
            CnaRange(
                vendor="Fortinet",
                product="FortiOS",
                package_name=None,
                default_status="unaffected",
                version="7.0.0",
                status="affected",
                less_than=None,
                less_than_or_equal="7.0.13",
                version_type="semver",
            ),
        ),
    )
    original = json.dumps({"id": cve_id, "lastModified": modified.isoformat()}).encode()
    return AdvisoryRecord(advisory, original)


def rows(engine: Engine) -> dict[str, list[tuple[object, ...]]]:
    with engine.connect() as connection:
        return {
            "cves": [
                tuple(row)
                for row in connection.execute(select(cves.c.cve_id, cves.c.last_modified))
            ],
            "nvd": [
                tuple(row)
                for row in connection.execute(
                    select(nvd_ranges.c.cve_id, nvd_ranges.c.end_excluding)
                )
            ],
            "cna": [
                tuple(row)
                for row in connection.execute(
                    select(cna_ranges.c.cve_id, cna_ranges.c.less_than_or_equal)
                )
            ],
        }


def test_new_advisories_are_written_with_their_ranges_and_compressed_original(
    engine: Engine,
) -> None:
    written = SqlAdvisoryStore(engine).write_advisories([record("CVE-2024-21762", MONDAY)])

    with engine.connect() as connection:
        original = connection.execute(select(cves.c.original)).scalar_one()
    assert written == 1
    assert rows(engine) == {
        "cves": [("CVE-2024-21762", "2026-10-26T12:00:00.000000+00:00")],
        "nvd": [("CVE-2024-21762", "7.0.14")],
        "cna": [("CVE-2024-21762", "7.0.13")],
    }
    assert zlib.decompress(original) == record("CVE-2024-21762", MONDAY).original_json


def test_a_newer_advisory_replaces_the_old_ranges(engine: Engine) -> None:
    store = SqlAdvisoryStore(engine)
    store.write_advisories([record("CVE-2024-21762", MONDAY, end_excluding="7.0.14")])

    written = store.write_advisories([record("CVE-2024-21762", TUESDAY, end_excluding="7.0.15")])

    assert written == 1
    assert rows(engine)["nvd"] == [("CVE-2024-21762", "7.0.15")]
    assert len(rows(engine)["cna"]) == 1


def test_an_advisory_not_newer_than_the_stored_one_is_skipped(engine: Engine) -> None:
    store = SqlAdvisoryStore(engine)
    store.write_advisories([record("CVE-2024-21762", TUESDAY, end_excluding="7.0.15")])

    written = store.write_advisories(
        [
            record("CVE-2024-21762", TUESDAY, end_excluding="7.0.99"),
            record("CVE-2024-21762", MONDAY, end_excluding="7.0.14"),
        ]
    )

    assert written == 0
    assert rows(engine)["nvd"] == [("CVE-2024-21762", "7.0.15")]


def test_the_latest_of_duplicates_in_one_batch_wins(engine: Engine) -> None:
    written = SqlAdvisoryStore(engine).write_advisories(
        [
            record("CVE-2024-21762", TUESDAY, end_excluding="7.0.15"),
            record("CVE-2024-21762", MONDAY, end_excluding="7.0.14"),
        ]
    )

    assert written == 1
    assert rows(engine)["nvd"] == [("CVE-2024-21762", "7.0.15")]


def test_the_freshness_of_the_nvd_copy_is_recorded_and_read_back(engine: Engine) -> None:
    store = SqlAdvisoryStore(engine)
    assert store.nvd_released_at() is None

    store.record_nvd_sync(NvdSyncKind.RECENT_CHANGES, released=MONDAY, synced_at=TUESDAY)

    with engine.connect() as connection:
        state = connection.execute(
            select(source_states).where(source_states.c.source == "nvd")
        ).one()
    assert store.nvd_released_at() == MONDAY
    assert state.version == "recent_changes"


def test_an_older_feed_does_not_move_the_freshness_of_the_copy_back(engine: Engine) -> None:
    store = SqlAdvisoryStore(engine)
    store.record_nvd_sync(NvdSyncKind.RECENT_CHANGES, released=TUESDAY, synced_at=TUESDAY)

    store.record_nvd_sync(NvdSyncKind.ALL, released=MONDAY, synced_at=TUESDAY)

    assert store.nvd_released_at() == TUESDAY


def unreadable_ids(engine: Engine) -> list[str]:
    with engine.connect() as connection:
        return list(connection.scalars(select(unreadable_cves.c.cve_id)))


def test_unreadable_cves_are_kept_until_a_readable_version_replaces_them(engine: Engine) -> None:
    store = SqlAdvisoryStore(engine)
    store.write_advisories([record("CVE-2024-21762", MONDAY)])

    store.record_unreadable(
        [
            UnreadableRecord("CVE-2024-21762", "CPE の形が変わっている"),
            UnreadableRecord(None, "id が無い"),
            UnreadableRecord("CVE-2024-21762", "2 度目"),
        ],
        seen_at=TUESDAY,
    )
    assert unreadable_ids(engine) == ["CVE-2024-21762"]

    store.write_advisories([record("CVE-2024-21762", TUESDAY)])
    assert unreadable_ids(engine) == []
