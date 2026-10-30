import zlib
from collections.abc import Sequence
from dataclasses import asdict
from datetime import UTC, datetime

from sqlalchemy import Connection, Engine, delete, insert, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import DBAPIError

from app.application.ports import (
    AdvisoryRecord,
    CatalogReplacement,
    NvdSyncKind,
    ReplicaError,
    UnreadableRecord,
)
from app.domain.exploited import ExploitedCatalog
from app.infrastructure.db.engine import TAKE_WRITE_LOCK
from app.infrastructure.db.tables import (
    cna_ranges,
    cves,
    exploited_vulnerabilities,
    nvd_ranges,
    source_states,
    unreadable_cves,
)

KEV_SOURCE = "kev"
NVD_SOURCE = "nvd"
MIGRATION_HINT = "`uv run alembic upgrade head` を流したか確かめる"


class SqlAdvisoryStore:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._writer = engine.execution_options(**{TAKE_WRITE_LOCK: True})

    def replace_exploited_catalog_if_newer(
        self, catalog: ExploitedCatalog, synced_at: datetime
    ) -> CatalogReplacement:
        try:
            with self._writer.begin() as connection:
                stored = _stored_release(connection, KEV_SOURCE)
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
            raise ReplicaError(f"手元の DB に書けない({error.orig})。{MIGRATION_HINT}") from error

    def nvd_released_at(self) -> datetime | None:
        try:
            with self._engine.connect() as connection:
                return _stored_release(connection, NVD_SOURCE)
        except DBAPIError as error:
            raise ReplicaError(f"手元の DB を読めない({error.orig})。{MIGRATION_HINT}") from error

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
                fresh: list[AdvisoryRecord] = []
                readable_ids: list[str] = []
                for cve_id, record in latest.items():
                    modified = _timestamp(record.advisory.last_modified)
                    if cve_id not in stored or modified >= stored[cve_id]:
                        readable_ids.append(cve_id)
                    if cve_id not in stored or modified > stored[cve_id]:
                        fresh.append(record)
                connection.execute(
                    delete(unreadable_cves).where(unreadable_cves.c.cve_id.in_(readable_ids))
                )
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
            raise ReplicaError(f"手元の DB に書けない({error.orig})。{MIGRATION_HINT}") from error

    def record_unreadable(self, records: Sequence[UnreadableRecord], seen_at: datetime) -> None:
        identified = {record.cve_id: record for record in records if record.cve_id is not None}
        if not identified:
            return
        try:
            with self._writer.begin() as connection:
                stored: dict[str, str] = {
                    cve_id: last_modified
                    for cve_id, last_modified in connection.execute(
                        select(cves.c.cve_id, cves.c.last_modified).where(
                            cves.c.cve_id.in_(identified)
                        )
                    )
                }
                rows = [
                    {"cve_id": cve_id, "reason": record.reason, "seen_at": _timestamp(seen_at)}
                    for cve_id, record in identified.items()
                    if cve_id not in stored
                    or record.last_modified is None
                    or _timestamp(record.last_modified) > stored[cve_id]
                ]
                if not rows:
                    return
                statement = sqlite_insert(unreadable_cves)
                connection.execute(
                    statement.on_conflict_do_update(
                        index_elements=[unreadable_cves.c.cve_id],
                        set_={
                            "reason": statement.excluded.reason,
                            "seen_at": statement.excluded.seen_at,
                        },
                    ),
                    rows,
                )
        except DBAPIError as error:
            raise ReplicaError(f"手元の DB に書けない({error.orig})。{MIGRATION_HINT}") from error

    def record_nvd_sync(self, kind: NvdSyncKind, released: datetime, synced_at: datetime) -> None:
        try:
            with self._writer.begin() as connection:
                stored = _stored_release(connection, NVD_SOURCE)
                newest = released if stored is None else max(stored, released)
                _record_state(connection, NVD_SOURCE, kind.value, newest, synced_at)
        except DBAPIError as error:
            raise ReplicaError(f"手元の DB に書けない({error.orig})。{MIGRATION_HINT}") from error


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="microseconds")


def _stored_release(connection: Connection, source: str) -> datetime | None:
    text = connection.scalar(
        select(source_states.c.released_at).where(source_states.c.source == source)
    )
    if text is None:
        return None
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as error:
        raise ReplicaError(f"手元の DB の {source} の公開日時が読めない: {text!r}") from error
    if moment.tzinfo is None:
        raise ReplicaError(f"手元の DB の {source} の公開日時にタイムゾーンが無い: {text!r}")
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
