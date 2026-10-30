import gzip
import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import respx

from app.application.ports import AdvisorySourceError
from app.domain.advisory import CnaRange, NvdRange
from app.infrastructure.nvd_feeds import FEED_BASE_URL, NvdFeedFile, NvdFeedFiles

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
        {
            "nodes": [
                {
                    "operator": "OR",
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:o:fortinet:fortios:7.4.2:*:*:*:*:*:*:*",
                        }
                    ],
                }
            ]
        },
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


def feed_bytes(*cves: dict[str, object]) -> tuple[bytes, str]:
    content = json.dumps(
        {"format": "NVD_CVE", "vulnerabilities": [{"cve": cve} for cve in cves]}
    ).encode()
    return gzip.compress(content), hashlib.sha256(content).hexdigest().upper()


def meta_text(sha256: str) -> str:
    return (
        f"lastModifiedDate:2026-10-29T03:01:50-04:00\r\nsize:1\r\ngzSize:1\r\nsha256:{sha256}\r\n"
    )


@pytest.fixture
def nvd() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        yield router


def feeds(directory: Path, this_year: int = 2026) -> NvdFeedFiles:
    return NvdFeedFiles(httpx.Client(), directory, this_year=this_year)


def test_records_carry_both_kinds_of_ranges_and_the_original_json(tmp_path: Path) -> None:
    path = tmp_path / "feed.json.gz"
    path.write_bytes(feed_bytes(CVE)[0])

    [record] = list(NvdFeedFile("2024", LAST_MODIFIED, path).records())

    advisory = record.advisory
    assert (advisory.cve_id, advisory.status) == ("CVE-2024-21762", "Analyzed")
    assert advisory.published == datetime(2024, 2, 9, 9, 15, 8, 87000, tzinfo=UTC)
    assert advisory.nvd_ranges == (
        NvdRange(
            "oracle", "mysql_connector/python", "*", "8.0.0", None, None, "8.0.14", on_platform=True
        ),
        NvdRange("fortinet", "fortios", "7.4.2", None, None, None, None, on_platform=False),
    )
    assert advisory.cna_ranges == (
        CnaRange(
            "Fortinet", "FortiOS", None, "unaffected", "7.4.0", "affected", None, "7.4.2", "semver"
        ),
        CnaRange("Fortinet", "FortiProxy", None, "affected", None, None, None, None, None),
    )
    assert json.loads(record.original_json) == CVE


def test_a_cve_without_its_required_fields_is_a_changed_format(tmp_path: Path) -> None:
    path = tmp_path / "feed.json.gz"
    path.write_bytes(feed_bytes({"id": "CVE-1"})[0])

    with pytest.raises(AdvisorySourceError, match="CVE の形が変わっている"):
        list(NvdFeedFile("2024", LAST_MODIFIED, path).records())


def test_a_verified_file_on_disk_is_used_without_downloading(
    tmp_path: Path, nvd: respx.MockRouter
) -> None:
    content, sha256 = feed_bytes(CVE)
    (tmp_path / "nvdcve-2.0-modified.json.gz").write_bytes(content)
    nvd.get(f"{FEED_BASE_URL}modified.meta").respond(text=meta_text(sha256))

    feed = feeds(tmp_path).recent_changes()

    assert (feed.name, feed.last_modified) == ("modified", LAST_MODIFIED)
    assert [record.advisory.cve_id for record in feed.records()] == ["CVE-2024-21762"]


def test_a_missing_file_is_downloaded_and_kept_under_its_name(
    tmp_path: Path, nvd: respx.MockRouter
) -> None:
    content, sha256 = feed_bytes(CVE)
    nvd.get(f"{FEED_BASE_URL}modified.meta").respond(text=meta_text(sha256))
    nvd.get(f"{FEED_BASE_URL}modified.json.gz").respond(content=content, headers={"etag": '"v1"'})

    feeds(tmp_path / "nvd").recent_changes()

    assert sorted(path.name for path in (tmp_path / "nvd").iterdir()) == [
        "nvdcve-2.0-modified.json.gz"
    ]


def test_a_partial_download_continues_from_where_it_stopped(
    tmp_path: Path, nvd: respx.MockRouter
) -> None:
    content, sha256 = feed_bytes(CVE)
    (tmp_path / "nvdcve-2.0-modified.json.gz.part").write_bytes(content[:10])
    (tmp_path / "nvdcve-2.0-modified.json.gz.etag").write_text('"v1"')
    asked: list[dict[str, str]] = []

    def partial(request: httpx.Request) -> httpx.Response:
        asked.append({key: request.headers[key] for key in ("range", "if-range")})
        return httpx.Response(206, content=content[10:])

    nvd.get(f"{FEED_BASE_URL}modified.meta").respond(text=meta_text(sha256))
    nvd.get(f"{FEED_BASE_URL}modified.json.gz").mock(side_effect=partial)

    feed = feeds(tmp_path).recent_changes()

    assert asked == [{"range": "bytes=10-", "if-range": '"v1"'}]
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


def test_a_dropped_connection_is_retried(tmp_path: Path, nvd: respx.MockRouter) -> None:
    content, sha256 = feed_bytes(CVE)
    nvd.get(f"{FEED_BASE_URL}modified.meta").respond(text=meta_text(sha256))
    nvd.get(f"{FEED_BASE_URL}modified.json.gz").mock(
        side_effect=[httpx.ReadTimeout("slow"), httpx.Response(200, content=content)]
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


def test_all_feeds_are_every_year_from_2002(tmp_path: Path, nvd: respx.MockRouter) -> None:
    content, sha256 = feed_bytes(CVE)
    for year in ("2002", "2003"):
        nvd.get(f"{FEED_BASE_URL}{year}.meta").respond(text=meta_text(sha256))
        nvd.get(f"{FEED_BASE_URL}{year}.json.gz").respond(content=content)

    names = [feed.name for feed in feeds(tmp_path, this_year=2003).all_feeds()]

    assert names == ["2002", "2003"]
