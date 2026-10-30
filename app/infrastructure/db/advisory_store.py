from datetime import datetime

from sqlalchemy import Engine, delete, insert, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.domain.exploited import ExploitedCatalog
from app.infrastructure.db.tables import exploited_vulnerabilities, source_states

KEV_SOURCE = "kev"


class SqlAdvisoryStore:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def exploited_catalog_version(self) -> str | None:
        with self._engine.connect() as connection:
            return connection.scalar(
                select(source_states.c.version).where(source_states.c.source == KEV_SOURCE)
            )

    def replace_exploited_catalog(self, catalog: ExploitedCatalog, synced_at: datetime) -> None:
        state = {"version": catalog.version, "synced_at": synced_at.isoformat()}
        with self._engine.begin() as connection:
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
