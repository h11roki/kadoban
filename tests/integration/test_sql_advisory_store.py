from collections.abc import Iterator
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, select

from app.application.ports import ReplicaError
from app.domain.exploited import ExploitedCatalog, ExploitedVulnerability
from app.infrastructure.db.advisory_store import SqlAdvisoryStore
from app.infrastructure.db.engine import create_sqlite_engine
from app.infrastructure.db.tables import exploited_vulnerabilities, source_states

ROOT = Path(__file__).resolve().parents[2]
RELEASED_28 = datetime(2026, 10, 28, 19, 0, tzinfo=UTC)
RELEASED_29 = datetime(2026, 10, 29, 19, 9, 34, 400300, tzinfo=UTC)


def exploited(cve_id: str, used_by_ransomware: bool) -> ExploitedVulnerability:
    return ExploitedVulnerability(
        cve_id=cve_id,
        date_added=date(2024, 2, 9),
        due_date=date(2024, 2, 16),
        used_by_ransomware=used_by_ransomware,
        required_action="Apply mitigations per vendor instructions.",
    )


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    database_path = tmp_path / "kadoban.db"
    config = Config(ROOT / "alembic.ini")
    config.attributes["database_path"] = database_path
    command.upgrade(config, "head")
    engine = create_sqlite_engine(database_path)
    yield engine
    engine.dispose()


def test_an_empty_store_has_no_catalog(engine: Engine) -> None:
    assert SqlAdvisoryStore(engine).exploited_catalog_released() is None


def test_replacing_the_catalog_drops_entries_that_left_it(engine: Engine) -> None:
    store = SqlAdvisoryStore(engine)
    second_sync = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)
    store.replace_exploited_catalog(
        ExploitedCatalog(
            "2026.10.28",
            RELEASED_28,
            (exploited("CVE-2024-21762", True), exploited("CVE-1", False)),
        ),
        synced_at=datetime(2026, 10, 29, 9, 0, tzinfo=UTC),
    )

    store.replace_exploited_catalog(
        ExploitedCatalog("2026.10.29", RELEASED_29, (exploited("CVE-2024-21762", True),)),
        synced_at=second_sync,
    )

    with engine.connect() as connection:
        table = exploited_vulnerabilities.c
        rows = connection.execute(select(table.cve_id, table.used_by_ransomware)).all()
        state = connection.execute(select(source_states)).one()
    assert [tuple(row) for row in rows] == [("CVE-2024-21762", True)]
    assert store.exploited_catalog_released() == RELEASED_29
    assert (state.version, datetime.fromisoformat(state.synced_at)) == ("2026.10.29", second_sync)


def test_a_database_without_the_migration_is_a_replica_error(tmp_path: Path) -> None:
    engine = create_sqlite_engine(tmp_path / "unmigrated.db")

    with pytest.raises(ReplicaError, match="読めない"):
        SqlAdvisoryStore(engine).exploited_catalog_released()

    engine.dispose()
