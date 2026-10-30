import gzip
import hashlib
import json
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
import ijson
from pydantic import BaseModel, ConfigDict, Field

from app.application.ports import (
    AdvisoryRecord,
    AdvisorySourceError,
    ReplicaError,
    UnreadableRecord,
)
from app.domain.advisory import Advisory, CnaRange, NvdRange

FEED_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"
FIRST_FEED_YEAR = 2002
RECENT_CHANGES_FEED = "modified"
DOWNLOAD_ATTEMPTS = 3
READ_CHUNK = 1 << 20
CPE_FIELDS = 13
REASON_LENGTH = 300


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
    operator: str | None = None
    negate: bool = False
    cpe_match: list[_CpeMatch] = Field(default_factory=list, alias="cpeMatch")


class _Configuration(_Model):
    operator: str | None = None
    nodes: list[_Node]

    @property
    def conditional(self) -> bool:
        return self.operator == "AND" or any(
            node.negate or node.operator == "AND" for node in self.nodes
        )


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
    gz_size: int


@dataclass(frozen=True)
class NvdFeedFile:
    name: str
    last_modified: datetime
    path: Path

    def records(self) -> Iterator[AdvisoryRecord | UnreadableRecord]:
        try:
            with gzip.open(self.path, "rb") as file:
                for item in ijson.items(file, "vulnerabilities.item.cve", use_float=True):
                    try:
                        advisory = _advisory(item)
                    except ValueError as error:
                        cve_id = item.get("id") if isinstance(item, dict) else None
                        yield UnreadableRecord(
                            cve_id if isinstance(cve_id, str) else None,
                            " ".join(str(error).split())[:REASON_LENGTH],
                        )
                        continue
                    yield AdvisoryRecord(
                        advisory,
                        json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode(),
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
            feed = self._fetch(str(year))
            if feed is not None:
                yield feed
            elif year != self._this_year:
                raise AdvisorySourceError(f"NVD に {year} 年の一括ファイルが無い")

    def recent_changes(self) -> NvdFeedFile:
        feed = self._fetch(RECENT_CHANGES_FEED)
        if feed is None:
            raise AdvisorySourceError("NVD に更新分のファイルが無い")
        return feed

    def _fetch(self, name: str) -> NvdFeedFile | None:
        meta = self._meta(name)
        if meta is None:
            return None
        path = self._directory / f"nvdcve-2.0-{name}.json.gz"
        try:
            if path.exists() and _matches(path, meta):
                return NvdFeedFile(name, meta.last_modified, path)
            for _ in range(DOWNLOAD_ATTEMPTS):
                _remove(path)
                self._download(name, path)
                if _matches(path, meta):
                    return NvdFeedFile(name, meta.last_modified, path)
                fresh_meta = self._meta(name)
                if fresh_meta is None:
                    return None
                meta = fresh_meta
            _remove(path)
        except OSError as error:
            raise ReplicaError(
                f"NVD のファイルの置き場 {self._directory} を使えない: {error}"
            ) from error
        raise AdvisorySourceError(
            f"NVD の {name} を {DOWNLOAD_ATTEMPTS} 回取り直しても .meta の sha256 と合わない"
        )

    def _meta(self, name: str) -> _Meta | None:
        try:
            response = self._client.get(f"{FEED_BASE_URL}{name}.meta")
            if response.status_code == httpx.codes.NOT_FOUND:
                return None
            response.raise_for_status()
        except httpx.HTTPError as error:
            raise AdvisorySourceError(f"NVD の {name} の .meta を取れなかった: {error}") from error
        fields = {
            key.strip(): value.strip()
            for key, value in (
                line.split(":", 1) for line in response.text.splitlines() if ":" in line
            )
        }
        try:
            return _Meta(
                last_modified=datetime.fromisoformat(fields["lastModifiedDate"]),
                sha256=fields["sha256"].lower(),
                gz_size=int(fields["gzSize"]),
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
            headers = {"Accept-Encoding": "identity"}
            if part.exists() and etag.exists():
                headers |= {"Range": f"bytes={part.stat().st_size}-", "If-Range": etag.read_text()}
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
                        for chunk in response.iter_raw(READ_CHUNK):
                            file.write(chunk)
            except httpx.HTTPStatusError as error:
                part.unlink(missing_ok=True)
                etag.unlink(missing_ok=True)
                if attempt == DOWNLOAD_ATTEMPTS:
                    raise AdvisorySourceError(f"NVD の {name} を取れなかった: {error}") from error
            except httpx.HTTPError as error:
                if attempt == DOWNLOAD_ATTEMPTS:
                    raise AdvisorySourceError(
                        f"NVD の {name} を {attempt} 回続きから取っても取り切れなかった: {error}"
                    ) from error
            else:
                part.replace(path)
                etag.unlink(missing_ok=True)
                return


def _checked(path: Path) -> Path:
    return path.with_name(f"{path.name}.sha256")


def _remove(path: Path) -> None:
    path.unlink(missing_ok=True)
    _checked(path).unlink(missing_ok=True)


def _matches(path: Path, meta: _Meta) -> bool:
    checked = _checked(path)
    if (
        checked.exists()
        and checked.read_text() == meta.sha256
        and path.stat().st_size == meta.gz_size
    ):
        return True
    digest = hashlib.sha256()
    try:
        with gzip.open(path, "rb") as file:
            while chunk := file.read(READ_CHUNK):
                digest.update(chunk)
    except (EOFError, zlib.error, gzip.BadGzipFile):
        return False
    if digest.hexdigest() != meta.sha256:
        return False
    checked.write_text(meta.sha256)
    return True


def _advisory(item: object) -> Advisory:
    cve = _Cve.model_validate(item)
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
                conditional=configuration.conditional,
            )
            for configuration in cve.configurations
            for node in configuration.nodes
            if not node.negate
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
    fields = [""]
    escaped = False
    for character in criteria:
        if escaped:
            fields[-1] += character
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("")
        else:
            fields[-1] += character
    if escaped or len(fields) != CPE_FIELDS or fields[:2] != ["cpe", "2.3"]:
        raise ValueError(f"CPE の形が変わっている: {criteria!r}")
    return fields[3], fields[4], fields[5]
