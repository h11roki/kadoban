import gzip
import hashlib
import json
import re
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
import ijson
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.application.ports import AdvisoryRecord, AdvisorySourceError
from app.domain.advisory import Advisory, CnaRange, NvdRange

FEED_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"
FIRST_FEED_YEAR = 2002
RECENT_CHANGES_FEED = "modified"
DOWNLOAD_ATTEMPTS = 3
READ_CHUNK = 1 << 20
UNESCAPED_COLON = re.compile(r"(?<!\\):")
ESCAPE = re.compile(r"\\(.)")


class _Model(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class _CpeMatch(_Model):
    vulnerable: bool
    criteria: str
    start_including: str | None = Field(None, alias="versionStartIncluding")
    start_excluding: str | None = Field(None, alias="versionStartExcluding")
    end_including: str | None = Field(None, alias="versionEndIncluding")
    end_excluding: str | None = Field(None, alias="versionEndExcluding")


class _Node(_Model):
    cpe_match: list[_CpeMatch] = Field(default_factory=list, alias="cpeMatch")


class _Configuration(_Model):
    operator: str | None = None
    nodes: list[_Node]


class _AffectedVersion(_Model):
    version: str | None = None
    status: str | None = None
    less_than: str | None = Field(None, alias="lessThan")
    less_than_or_equal: str | None = Field(None, alias="lessThanOrEqual")
    version_type: str | None = Field(None, alias="versionType")


class _AffectedData(_Model):
    vendor: str | None = None
    product: str | None = None
    package_name: str | None = Field(None, alias="packageName")
    default_status: str | None = Field(None, alias="defaultStatus")
    versions: list[_AffectedVersion] = Field(default_factory=list)


class _Affected(_Model):
    affected_data: list[_AffectedData] = Field(default_factory=list, alias="affectedData")


class _Cve(_Model):
    id: str
    published: datetime
    last_modified: datetime = Field(alias="lastModified")
    vuln_status: str = Field(alias="vulnStatus")
    configurations: list[_Configuration] = Field(default_factory=list)
    affected: list[_Affected] = Field(default_factory=list)


@dataclass(frozen=True)
class _Meta:
    last_modified: datetime
    sha256: str


@dataclass(frozen=True)
class NvdFeedFile:
    name: str
    last_modified: datetime
    path: Path

    def records(self) -> Iterator[AdvisoryRecord]:
        try:
            with gzip.open(self.path, "rb") as file:
                for item in ijson.items(file, "vulnerabilities.item.cve", use_float=True):
                    yield AdvisoryRecord(
                        advisory=_advisory(self.name, item),
                        original_json=json.dumps(
                            item, ensure_ascii=False, separators=(",", ":")
                        ).encode(),
                    )
        except (OSError, EOFError, zlib.error, ijson.JSONError) as error:
            raise AdvisorySourceError(f"NVD の {self.name} を読めない: {error}") from error


class NvdFeedFiles:
    def __init__(self, client: httpx.Client, directory: Path, this_year: int) -> None:
        self._client = client
        self._directory = directory
        self._this_year = this_year

    def all_feeds(self) -> Iterator[NvdFeedFile]:
        for year in range(FIRST_FEED_YEAR, self._this_year + 1):
            yield self._fetch(str(year))

    def recent_changes(self) -> NvdFeedFile:
        return self._fetch(RECENT_CHANGES_FEED)

    def _fetch(self, name: str) -> NvdFeedFile:
        path = self._directory / f"nvdcve-2.0-{name}.json.gz"
        meta = self._meta(name)
        if path.exists() and _content_sha256(path) == meta.sha256:
            return NvdFeedFile(name, meta.last_modified, path)
        for _ in range(DOWNLOAD_ATTEMPTS):
            path.unlink(missing_ok=True)
            self._download(name, path)
            if _content_sha256(path) == meta.sha256:
                return NvdFeedFile(name, meta.last_modified, path)
            meta = self._meta(name)
        path.unlink(missing_ok=True)
        raise AdvisorySourceError(
            f"NVD の {name} を {DOWNLOAD_ATTEMPTS} 回取り直しても .meta の sha256 と合わない"
        )

    def _meta(self, name: str) -> _Meta:
        try:
            response = self._client.get(f"{FEED_BASE_URL}{name}.meta")
            response.raise_for_status()
        except httpx.HTTPError as error:
            raise AdvisorySourceError(f"NVD の {name} の .meta を取れなかった: {error}") from error
        fields = dict(line.split(":", 1) for line in response.text.splitlines() if ":" in line)
        try:
            return _Meta(
                last_modified=datetime.fromisoformat(fields["lastModifiedDate"].strip()),
                sha256=fields["sha256"].strip().lower(),
            )
        except (KeyError, ValueError) as error:
            raise AdvisorySourceError(
                f"NVD の {name} の .meta の形が変わっている: {response.text[:200]!r}"
            ) from error

    def _download(self, name: str, path: Path) -> None:
        self._directory.mkdir(parents=True, exist_ok=True)
        part = path.with_name(f"{path.name}.part")
        etag = path.with_name(f"{path.name}.etag")
        for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
            headers = {}
            if part.exists() and etag.exists():
                headers = {"Range": f"bytes={part.stat().st_size}-", "If-Range": etag.read_text()}
            try:
                with self._client.stream(
                    "GET", f"{FEED_BASE_URL}{name}.json.gz", headers=headers
                ) as response:
                    if response.status_code != httpx.codes.PARTIAL_CONTENT:
                        response.raise_for_status()
                        etag.unlink(missing_ok=True)
                        part.unlink(missing_ok=True)
                        if "etag" in response.headers:
                            etag.write_text(response.headers["etag"])
                    with part.open("ab") as file:
                        for chunk in response.iter_bytes(READ_CHUNK):
                            file.write(chunk)
            except httpx.HTTPStatusError as error:
                part.unlink(missing_ok=True)
                etag.unlink(missing_ok=True)
                if attempt == DOWNLOAD_ATTEMPTS:
                    raise AdvisorySourceError(f"NVD の {name} を取れなかった: {error}") from error
            except httpx.TransportError as error:
                if attempt == DOWNLOAD_ATTEMPTS:
                    raise AdvisorySourceError(
                        f"NVD の {name} を {attempt} 回続きから取っても取り切れなかった: {error}"
                    ) from error
            else:
                part.replace(path)
                etag.unlink(missing_ok=True)
                return


def _content_sha256(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with gzip.open(path, "rb") as file:
            while chunk := file.read(READ_CHUNK):
                digest.update(chunk)
    except (OSError, EOFError, zlib.error):
        return None
    return digest.hexdigest()


def _advisory(feed: str, item: object) -> Advisory:
    try:
        cve = _Cve.model_validate(item)
    except ValidationError as error:
        raise AdvisorySourceError(f"NVD の {feed} の CVE の形が変わっている: {error}") from error
    return Advisory(
        cve_id=cve.id,
        published=_utc(cve.published),
        last_modified=_utc(cve.last_modified),
        status=cve.vuln_status,
        nvd_ranges=tuple(
            NvdRange(
                *_vendor_product_version(match.criteria),
                start_including=match.start_including,
                start_excluding=match.start_excluding,
                end_including=match.end_including,
                end_excluding=match.end_excluding,
                on_platform=configuration.operator == "AND",
            )
            for configuration in cve.configurations
            for node in configuration.nodes
            for match in node.cpe_match
            if match.vulnerable
        ),
        cna_ranges=tuple(
            CnaRange(
                vendor=data.vendor,
                product=data.product,
                package_name=data.package_name,
                default_status=data.default_status,
                version=version.version,
                status=version.status,
                less_than=version.less_than,
                less_than_or_equal=version.less_than_or_equal,
                version_type=version.version_type,
            )
            for affected in cve.affected
            for data in affected.affected_data
            for version in (data.versions or [_AffectedVersion()])
        ),
    )


def _utc(moment: datetime) -> datetime:
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


def _vendor_product_version(criteria: str) -> tuple[str, str, str]:
    parts = [ESCAPE.sub(r"\1", part) for part in UNESCAPED_COLON.split(criteria)]
    if len(parts) != 13 or parts[:2] != ["cpe", "2.3"]:
        raise AdvisorySourceError(f"NVD の CPE の形が変わっている: {criteria!r}")
    return parts[3], parts[4], parts[5]
