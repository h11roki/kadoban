from datetime import datetime

from sqlalchemy import Connection, Engine, delete, insert, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import DBAPIError

from app.application.ports import ReplicaError
from app.domain.exploited import ExploitedCatalog
from app.infrastructure.db.tables import exploited_vulnerabilities, source_states

KEV_SOURCE = "kev"


class SqlAdvisoryStore:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def exploited_catalog_released(self) -> datetime | None:
        try:
            with self._engine.connect() as connection:
                return _stored_release(connection)
        except DBAPIError as error:
            raise ReplicaError(f"手元の DB を読めない: {error.orig}") from error

    def replace_exploited_catalog_if_newer(
        self, catalog: ExploitedCatalog, synced_at: datetime
    ) -> bool:
        state = {
            "version": catalog.version,
            "released_at": catalog.released.isoformat(timespec="microseconds"),
            "synced_at": synced_at.isoformat(timespec="microseconds"),
        }
        try:
            with self._engine.begin() as connection:
                stored = _stored_release(connection)
                if stored is not None and stored >= catalog.released:
                    return False
                connection.execute(delete(exploited_vulnerabilities))
                connection.execute(
                    insert(exploited_vulnerabilities),
                    [
                        {
                            "cve_id": vulnerability.cve_id,
                            "date_added": vulnerability.date_added,
                            "due_date": vulnerability.due_date,
                            "used_by_ransomware": vulnerability.used_by_ransomware,
                            "required_action": vulnerability.required_action,
                        }
                        for vulnerability in catalog.vulnerabilities
                    ],
                )
                connection.execute(
                    sqlite_insert(source_states)
                    .values(source=KEV_SOURCE, **state)
                    .on_conflict_do_update(index_elements=[source_states.c.source], set_=state)
                )
                return True
        except DBAPIError as error:
            raise ReplicaError(f"手元の DB に書けない: {error.orig}") from error


def _stored_release(connection: Connection) -> datetime | None:
    released = connection.scalar(
        select(source_states.c.released_at).where(source_states.c.source == KEV_SOURCE)
    )
    if released is None:
        return None
    try:
        return datetime.fromisoformat(released)
    except ValueError as error:
        raise ReplicaError(f"手元の DB の KEV の公開日時が読めない: {released!r}") from error
