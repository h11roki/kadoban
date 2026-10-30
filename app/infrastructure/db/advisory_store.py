from datetime import datetime

from sqlalchemy import Engine, delete, insert, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import DBAPIError

from app.application.ports import CatalogReplacement, ReplicaError
from app.domain.exploited import ExploitedCatalog
from app.infrastructure.db.engine import TAKE_WRITE_LOCK
from app.infrastructure.db.tables import exploited_vulnerabilities, source_states

KEV_SOURCE = "kev"


class SqlAdvisoryStore:
    def __init__(self, engine: Engine) -> None:
        self._writer = engine.execution_options(**{TAKE_WRITE_LOCK: True})

    def replace_exploited_catalog_if_newer(
        self, catalog: ExploitedCatalog, synced_at: datetime
    ) -> CatalogReplacement:
        state = {
            "version": catalog.version,
            "released_at": catalog.released.isoformat(timespec="microseconds"),
            "synced_at": synced_at.isoformat(timespec="microseconds"),
        }
        try:
            with self._writer.begin() as connection:
                stored_text = connection.scalar(
                    select(source_states.c.released_at).where(source_states.c.source == KEV_SOURCE)
                )
                if stored_text is not None:
                    try:
                        stored = datetime.fromisoformat(stored_text)
                    except ValueError as error:
                        raise ReplicaError(
                            f"手元の DB の KEV の公開日時が読めない: {stored_text!r}"
                        ) from error
                    if stored.tzinfo is None:
                        raise ReplicaError(
                            f"手元の DB の KEV の公開日時にタイムゾーンが無い: {stored_text!r}"
                        )
                    if stored == catalog.released:
                        return CatalogReplacement.SAME_RELEASE
                    if stored > catalog.released:
                        return CatalogReplacement.OLDER_RELEASE
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
                return CatalogReplacement.REPLACED
        except DBAPIError as error:
            raise ReplicaError(f"手元の DB に書けない: {error.orig}") from error
