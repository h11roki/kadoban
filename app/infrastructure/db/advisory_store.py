import zlib
from collections.abc import Sequence
from dataclasses import asdict
from datetime import UTC, datetime

from sqlalchemy import Column, Connection, Engine, delete, insert, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import DBAPIError

from app.application.ports import AdvisoryRecord, CatalogReplacement, NvdSyncKind, ReplicaError
from app.domain.exploited import ExploitedCatalog
from app.infrastructure.db.engine import TAKE_WRITE_LOCK
from app.infrastructure.db.tables import (
    cna_ranges,
    cves,
    exploited_vulnerabilities,
    nvd_ranges,
    source_states,
)

KEV_SOURCE = "kev"
NVD_SOURCE = "nvd"


class SqlAdvisoryStore:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._writer = engine.execution_options(**{TAKE_WRITE_LOCK: True})

    def replace_exploited_catalog_if_newer(
        self, catalog: ExploitedCatalog, synced_at: datetime
    ) -> CatalogReplacement:
        try:
            with self._writer.begin() as connection:
                stored = _stored_time(connection, KEV_SOURCE, source_states.c.released_at)
                if stored == catalog.released:
                    return CatalogReplacement.SAME_RELEASE
                if stored is not None and stored > catalog.released:
                    return CatalogReplacement.OLDER_RELEASE
                connection.execute(delete(exploited_vulnerabilities))
                connection.execute(
                    insert(exploited_vulnerabilities),
                    [asdict(vulnerability) for vulnerability in catalog.vulnerabilities],
                )
                _record_state(connection, KEV_SOURCE, catalog.version, catalog.released, synced_at)
                return CatalogReplacement.REPLACED
        except DBAPIError as error:
            raise ReplicaError(f"手元の DB に書けない: {error.orig}") from error

    def nvd_synced_at(self) -> datetime | None:
        try:
            with self._engine.connect() as connection:
                return _stored_time(connection, NVD_SOURCE, source_states.c.synced_at)
        except DBAPIError as error:
            raise ReplicaError(f"手元の DB を読めない: {error.orig}") from error

    def write_advisories(self, records: Sequence[AdvisoryRecord]) -> int:
        latest: dict[str, AdvisoryRecord] = {}
        for record in records:
            known = latest.get(record.advisory.cve_id)
            if known is None or record.advisory.last_modified > known.advisory.last_modified:
                latest[record.advisory.cve_id] = record
        try:
            with self._writer.begin() as connection:
                stored: dict[str, str] = {
                    cve_id: last_modified
                    for cve_id, last_modified in connection.execute(
                        select(cves.c.cve_id, cves.c.last_modified).where(cves.c.cve_id.in_(latest))
                    )
                }
                fresh = [
                    record
                    for cve_id, record in latest.items()
                    if cve_id not in stored
                    or _timestamp(record.advisory.last_modified) > stored[cve_id]
                ]
                if not fresh:
                    return 0
                fresh_ids = [record.advisory.cve_id for record in fresh]
                for table in (cves, nvd_ranges, cna_ranges):
                    connection.execute(delete(table).where(table.c.cve_id.in_(fresh_ids)))
                connection.execute(
                    insert(cves),
                    [
                        {
                            "cve_id": record.advisory.cve_id,
                            "published": _timestamp(record.advisory.published),
                            "last_modified": _timestamp(record.advisory.last_modified),
                            "status": record.advisory.status,
                            "original": zlib.compress(record.original_json),
                        }
                        for record in fresh
                    ],
                )
                nvd_rows = [
                    {"cve_id": record.advisory.cve_id, **asdict(nvd_range)}
                    for record in fresh
                    for nvd_range in record.advisory.nvd_ranges
                ]
                if nvd_rows:
                    connection.execute(insert(nvd_ranges), nvd_rows)
                cna_rows = [
                    {"cve_id": record.advisory.cve_id, **asdict(cna_range)}
                    for record in fresh
                    for cna_range in record.advisory.cna_ranges
                ]
                if cna_rows:
                    connection.execute(insert(cna_ranges), cna_rows)
                return len(fresh)
        except DBAPIError as error:
            raise ReplicaError(f"手元の DB に書けない: {error.orig}") from error

    def record_nvd_sync(self, kind: NvdSyncKind, released: datetime, synced_at: datetime) -> None:
        try:
            with self._writer.begin() as connection:
                _record_state(connection, NVD_SOURCE, kind.value, released, synced_at)
        except DBAPIError as error:
            raise ReplicaError(f"手元の DB に書けない: {error.orig}") from error


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="microseconds")


def _stored_time(connection: Connection, source: str, column: Column[str]) -> datetime | None:
    text = connection.scalar(select(column).where(source_states.c.source == source))
    if text is None:
        return None
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as error:
        raise ReplicaError(
            f"手元の DB の {source} の {column.name} が読めない: {text!r}"
        ) from error
    if moment.tzinfo is None:
        raise ReplicaError(f"手元の DB の {source} の {column.name} にタイムゾーンが無い: {text!r}")
    return moment


def _record_state(
    connection: Connection, source: str, version: str, released: datetime, synced_at: datetime
) -> None:
    state = {
        "version": version,
        "released_at": _timestamp(released),
        "synced_at": _timestamp(synced_at),
    }
    connection.execute(
        sqlite_insert(source_states)
        .values(source=source, **state)
        .on_conflict_do_update(index_elements=[source_states.c.source], set_=state)
    )
