import gzip
import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import respx

from app.application.ports import (
    AdvisoryRecord,
    AdvisorySourceError,
    ReplicaError,
    UnreadableRecord,
)
from app.domain.advisory import CnaRange, NvdRange
from app.infrastructure.nvd_feeds import FEED_BASE_URL, NvdFeedFile, NvdFeedFiles

FORTIOS_MATCH = {"vulnerable": True, "criteria": "cpe:2.3:o:fortinet:fortios:7.4.2:*:*:*:*:*:*:*"}

CVE: dict[str, object] = {
    "id": "CVE-2024-21762",
    "published": "2024-02-09T09:15:08.087",
    "lastModified": "2026-10-29T14:15:16.243",
    "vulnStatus": "Analyzed",
    "configurations": [
        {
            "operator": "AND",
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:oracle:mysql_connector\\/python:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "8.0.0",
                            "versionEndExcluding": "8.0.14",
                        }
                    ],
                },
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux:-:*:*:*:*:*:*:*"}
                    ],
                },
            ],
        },
        {"nodes": [{"operator": "OR", "cpeMatch": [FORTIOS_MATCH]}]},
    ],
    "affected": [
        {
            "source": "psirt@fortinet.com",
            "affectedData": [
                {
                    "vendor": "Fortinet",
                    "product": "FortiOS",
                    "defaultStatus": "unaffected",
                    "versions": [
                        {
                            "version": "7.4.0",
                            "lessThanOrEqual": "7.4.2",
                            "status": "affected",
                            "versionType": "semver",
                        }
                    ],
                },
                {"vendor": "Fortinet", "product": "FortiProxy", "defaultStatus": "affected"},
            ],
        }
    ],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
}

LAST_MODIFIED = datetime(2026, 10, 29, 3, 1, 50, tzinfo=timezone(timedelta(hours=-4)))


def cve(cve_id: str, **fields: object) -> dict[str, object]:
    return {**CVE, "id": cve_id, **fields}


def feed_bytes(*cves: dict[str, object]) -> tuple[bytes, str]:
    content = json.dumps(
        {"format": "NVD_CVE", "vulnerabilities": [{"cve": item} for item in cves]}
    ).encode()
    return gzip.compress(content), hashlib.sha256(content).hexdigest().upper()


def meta_text(sha256: str, gz_size: int = 1) -> str:
    return (
        "lastModifiedDate:2026-10-29T03:01:50-04:00\r\n"
        f"size:1\r\nzipSize:1\r\ngzSize:{gz_size}\r\nsha256:{sha256}\r\n"
    )


def read(tmp_path: Path, *cves: dict[str, object]) -> list[AdvisoryRecord | UnreadableRecord]:
    path = tmp_path / "feed.json.gz"
    path.write_bytes(feed_bytes(*cves)[0])
    return list(NvdFeedFile("2024", LAST_MODIFIED, path).records())


def advisory_record(record: AdvisoryRecord | UnreadableRecord) -> AdvisoryRecord:
    assert isinstance(record, AdvisoryRecord)
    return record


@pytest.fixture
def nvd() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        yield router


def feeds(directory: Path, this_year: int = 2026) -> NvdFeedFiles:
    return NvdFeedFiles(httpx.Client(), directory, this_year=this_year)


def test_records_carry_both_kinds_of_ranges_and_the_original_json(tmp_path: Path) -> None:
    [record] = map(advisory_record, read(tmp_path, CVE))

    advisory = record.advisory
    assert (advisory.cve_id, advisory.status) == ("CVE-2024-21762", "Analyzed")
    assert advisory.published == datetime(2024, 2, 9, 9, 15, 8, 87000, tzinfo=UTC)
    assert advisory.nvd_ranges == (
        NvdRange("oracle", "mysql_connector/python", "*", "8.0.0", None, None, "8.0.14", True),
        NvdRange("fortinet", "fortios", "7.4.2", None, None, None, None, False),
    )
    assert advisory.cna_ranges == (
        CnaRange(
            "Fortinet", "FortiOS", None, "unaffected", "7.4.0", "affected", None, "7.4.2", "semver"
        ),
        CnaRange("Fortinet", "FortiProxy", None, "affected", None, None, None, None, None),
    )
    assert json.loads(record.original_json) == CVE


def test_a_negated_node_is_not_a_range_and_makes_its_configuration_conditional(
    tmp_path: Path,
) -> None:
    excluded = {"vulnerable": True, "criteria": "cpe:2.3:o:fortinet:fortios:7.4.1:*:*:*:*:*:*:*"}
    configuration = {
        "nodes": [
            {"operator": "OR", "cpeMatch": [FORTIOS_MATCH]},
            {"operator": "OR", "negate": True, "cpeMatch": [excluded]},
        ]
    }

    [record] = map(advisory_record, read(tmp_path, cve("CVE-1", configurations=[configuration])))

    assert [(item.version, item.conditional) for item in record.advisory.nvd_ranges] == [
        ("7.4.2", True)
    ]


def test_an_escaped_backslash_before_a_separator_is_kept_in_the_field(tmp_path: Path) -> None:
    match = {"vulnerable": True, "criteria": "cpe:2.3:a:vendor:prod\\\\:1.0:*:*:*:*:*:*:*"}
    configuration = {"nodes": [{"operator": "OR", "cpeMatch": [match]}]}

    [record] = map(advisory_record, read(tmp_path, cve("CVE-1", configurations=[configuration])))

    [nvd_range] = record.advisory.nvd_ranges
    assert (nvd_range.product, nvd_range.version) == ("prod\\", "1.0")


def test_an_unreadable_cve_is_reported_and_the_rest_are_read(tmp_path: Path) -> None:
    broken: dict[str, object] = {"id": "CVE-2", "published": "2024-02-09T09:15:08.087"}
    bad_cpe = {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:x"}]}]}

    records = read(tmp_path, cve("CVE-1"), broken, cve("CVE-3", configurations=[bad_cpe]))

    assert isinstance(records[0], AdvisoryRecord)
    assert [
        (record.cve_id, "lastModified" in record.reason or "CPE" in record.reason)
        for record in records[1:]
        if isinstance(record, UnreadableRecord)
    ] == [("CVE-2", True), ("CVE-3", True)]


def test_a_file_that_is_not_gzip_cannot_be_read(tmp_path: Path) -> None:
    path = tmp_path / "feed.json.gz"
    path.write_bytes(b"not gzip")

    with pytest.raises(AdvisorySourceError, match="読めない"):
        list(NvdFeedFile("2024", LAST_MODIFIED, path).records())


def test_a_checked_file_on_disk_is_used_without_downloading(
    tmp_path: Path, nvd: respx.MockRouter
) -> None:
    content, sha256 = feed_bytes(CVE)
    (tmp_path / "nvdcve-2.0-modified.json.gz").write_bytes(content)
    nvd.get(f"{FEED_BASE_URL}modified.meta").respond(text=meta_text(sha256, len(content)))

    feed = feeds(tmp_path).recent_changes()

    assert (feed.name, feed.last_modified) == ("modified", LAST_MODIFIED)
    assert (tmp_path / "nvdcve-2.0-modified.json.gz.sha256").read_text() == sha256.lower()
    assert [advisory_record(record).advisory.cve_id for record in feed.records()] == [
        "CVE-2024-21762"
    ]


def test_a_file_checked_before_is_not_hashed_again(tmp_path: Path, nvd: respx.MockRouter) -> None:
    content, sha256 = feed_bytes(CVE)
    path = tmp_path / "nvdcve-2.0-modified.json.gz"
    path.write_bytes(b"x" * len(content))
    (tmp_path / "nvdcve-2.0-modified.json.gz.sha256").write_text(sha256.lower())
    nvd.get(f"{FEED_BASE_URL}modified.meta").respond(text=meta_text(sha256, len(content)))

    feed = feeds(tmp_path).recent_changes()

    assert feed.path == path


def test_a_missing_file_is_downloaded_uncompressed_and_kept_under_its_name(
    tmp_path: Path, nvd: respx.MockRouter
) -> None:
    content, sha256 = feed_bytes(CVE)
    asked: list[str] = []

    def whole(request: httpx.Request) -> httpx.Response:
        asked.append(request.headers["accept-encoding"])
        return httpx.Response(200, content=content, headers={"etag": '"v1"'})

    nvd.get(f"{FEED_BASE_URL}modified.meta").respond(text=meta_text(sha256))
    nvd.get(f"{FEED_BASE_URL}modified.json.gz").mock(side_effect=whole)

    feeds(tmp_path / "nvd").recent_changes()

    assert asked == ["identity"]
    assert sorted(path.name for path in (tmp_path / "nvd").iterdir()) == [
        "nvdcve-2.0-modified.json.gz",
        "nvdcve-2.0-modified.json.gz.sha256",
    ]


def test_a_partial_download_continues_from_where_it_stopped(
    tmp_path: Path, nvd: respx.MockRouter
) -> None:
    content, sha256 = feed_bytes(CVE)
    (tmp_path / "nvdcve-2.0-modified.json.gz.part").write_bytes(content[:10])
    (tmp_path / "nvdcve-2.0-modified.json.gz.etag").write_text('"v1"')
    asked: list[tuple[str, str]] = []

    def rest(request: httpx.Request) -> httpx.Response:
        asked.append((request.headers["range"], request.headers["if-range"]))
        return httpx.Response(206, content=content[10:])

    nvd.get(f"{FEED_BASE_URL}modified.meta").respond(text=meta_text(sha256))
    nvd.get(f"{FEED_BASE_URL}modified.json.gz").mock(side_effect=rest)

    feed = feeds(tmp_path).recent_changes()

    assert asked == [("bytes=10-", '"v1"')]
    assert feed.path.read_bytes() == content


def test_a_partial_download_restarts_when_the_file_changed_on_the_server(
    tmp_path: Path, nvd: respx.MockRouter
) -> None:
    content, sha256 = feed_bytes(CVE)
    (tmp_path / "nvdcve-2.0-modified.json.gz.part").write_bytes(b"stale bytes")
    (tmp_path / "nvdcve-2.0-modified.json.gz.etag").write_text('"old"')
    nvd.get(f"{FEED_BASE_URL}modified.meta").respond(text=meta_text(sha256))
    nvd.get(f"{FEED_BASE_URL}modified.json.gz").respond(content=content, headers={"etag": '"v2"'})

    feed = feeds(tmp_path).recent_changes()

    assert feed.path.read_bytes() == content


@pytest.mark.parametrize(
    "first_failure",
    [httpx.ReadTimeout("slow"), httpx.DecodingError("garbled"), httpx.TooManyRedirects("loop")],
)
def test_a_failed_transfer_is_tried_again(
    tmp_path: Path, nvd: respx.MockRouter, first_failure: httpx.HTTPError
) -> None:
    content, sha256 = feed_bytes(CVE)
    nvd.get(f"{FEED_BASE_URL}modified.meta").respond(text=meta_text(sha256))
    nvd.get(f"{FEED_BASE_URL}modified.json.gz").mock(
        side_effect=[first_failure, httpx.Response(200, content=content)]
    )

    feed = feeds(tmp_path).recent_changes()

    assert feed.path.read_bytes() == content


def test_a_file_that_never_matches_its_meta_is_refused_and_removed(
    tmp_path: Path, nvd: respx.MockRouter
) -> None:
    content, _ = feed_bytes(CVE)
    meta = nvd.get(f"{FEED_BASE_URL}modified.meta").respond(text=meta_text("0" * 64))
    nvd.get(f"{FEED_BASE_URL}modified.json.gz").respond(content=content)

    with pytest.raises(AdvisorySourceError, match="sha256 と合わない"):
        feeds(tmp_path).recent_changes()

    assert meta.call_count == 4
    assert list(tmp_path.iterdir()) == []


def test_a_meta_without_a_checksum_is_a_changed_format(
    tmp_path: Path, nvd: respx.MockRouter
) -> None:
    nvd.get(f"{FEED_BASE_URL}modified.meta").respond(
        text="lastModifiedDate:2026-10-29T03:01:50-04:00"
    )

    with pytest.raises(AdvisorySourceError, match=".meta の形が変わっている"):
        feeds(tmp_path).recent_changes()


def test_a_directory_that_cannot_hold_files_is_a_replica_error(
    tmp_path: Path, nvd: respx.MockRouter
) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("")
    content, sha256 = feed_bytes(CVE)
    nvd.get(f"{FEED_BASE_URL}modified.meta").respond(text=meta_text(sha256))
    nvd.get(f"{FEED_BASE_URL}modified.json.gz").respond(content=content)

    with pytest.raises(ReplicaError, match="置き場"):
        feeds(blocker / "nvd").recent_changes()


def test_all_feeds_are_every_year_from_2002_and_skip_a_current_year_not_yet_published(
    tmp_path: Path, nvd: respx.MockRouter
) -> None:
    content, sha256 = feed_bytes(CVE)
    for year in ("2002", "2003"):
        nvd.get(f"{FEED_BASE_URL}{year}.meta").respond(text=meta_text(sha256))
        nvd.get(f"{FEED_BASE_URL}{year}.json.gz").respond(content=content)
    nvd.get(f"{FEED_BASE_URL}2004.meta").respond(status_code=404)

    names = [feed.name for feed in feeds(tmp_path, this_year=2004).all_feeds()]

    assert names == ["2002", "2003"]


def test_a_missing_past_year_is_an_error(tmp_path: Path, nvd: respx.MockRouter) -> None:
    nvd.get(f"{FEED_BASE_URL}2002.meta").respond(status_code=404)

    with pytest.raises(AdvisorySourceError, match="2002 年の一括ファイルが無い"):
        list(feeds(tmp_path, this_year=2003).all_feeds())
