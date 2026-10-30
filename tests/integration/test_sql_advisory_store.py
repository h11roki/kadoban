from collections.abc import Iterator
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, select, update

from app.application.ports import ReplicaError
from app.domain.exploited import ExploitedCatalog, ExploitedVulnerability
from app.infrastructure.db.advisory_store import SqlAdvisoryStore
from app.infrastructure.db.engine import create_sqlite_engine
from app.infrastructure.db.tables import exploited_vulnerabilities, source_states

ROOT = Path(__file__).resolve().parents[2]
RELEASED_28 = datetime(2026, 10, 28, 19, 0, tzinfo=UTC)
RELEASED_29 = datetime(2026, 10, 29, 19, 9, 34, 400300, tzinfo=UTC)
SYNCED = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)


def exploited(cve_id: str, used_by_ransomware: bool = True) -> ExploitedVulnerability:
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
    config.attributes["configure_logger"] = False
    command.upgrade(config, "head")
    engine = create_sqlite_engine(database_path)
    yield engine
    engine.dispose()


def stored_cve_ids(engine: Engine) -> list[str]:
    with engine.connect() as connection:
        return list(connection.scalars(select(exploited_vulnerabilities.c.cve_id)))


def test_an_empty_store_has_no_catalog(engine: Engine) -> None:
    assert SqlAdvisoryStore(engine).exploited_catalog_released() is None


def test_a_newer_catalog_replaces_entries_and_records_its_release(engine: Engine) -> None:
    store = SqlAdvisoryStore(engine)
    store.replace_exploited_catalog_if_newer(
        ExploitedCatalog(
            "2026.10.28", RELEASED_28, (exploited("CVE-2024-21762"), exploited("CVE-1"))
        ),
        synced_at=datetime(2026, 10, 29, 9, 0, tzinfo=UTC),
    )

    replaced = store.replace_exploited_catalog_if_newer(
        ExploitedCatalog("2026.10.29", RELEASED_29, (exploited("CVE-2024-21762"),)),
        synced_at=SYNCED,
    )

    with engine.connect() as connection:
        state = connection.execute(select(source_states)).one()
    assert replaced is True
    assert stored_cve_ids(engine) == ["CVE-2024-21762"]
    assert store.exploited_catalog_released() == RELEASED_29
    assert (state.version, datetime.fromisoformat(state.synced_at)) == ("2026.10.29", SYNCED)


@pytest.mark.parametrize("released", [RELEASED_28, RELEASED_29])
def test_a_catalog_not_newer_than_the_stored_one_is_not_written(
    engine: Engine, released: datetime
) -> None:
    store = SqlAdvisoryStore(engine)
    store.replace_exploited_catalog_if_newer(
        ExploitedCatalog("2026.10.29", RELEASED_29, (exploited("CVE-2024-21762"),)),
        synced_at=SYNCED,
    )

    replaced = store.replace_exploited_catalog_if_newer(
        ExploitedCatalog("old", released, (exploited("CVE-1"),)), synced_at=SYNCED
    )

    assert replaced is False
    assert stored_cve_ids(engine) == ["CVE-2024-21762"]
    assert store.exploited_catalog_released() == RELEASED_29


def test_a_database_without_the_migration_is_a_replica_error(tmp_path: Path) -> None:
    engine = create_sqlite_engine(tmp_path / "unmigrated.db")

    with pytest.raises(ReplicaError, match="no such table"):
        SqlAdvisoryStore(engine).exploited_catalog_released()

    engine.dispose()


def test_a_file_that_is_not_a_database_is_a_replica_error(tmp_path: Path) -> None:
    path = tmp_path / "kadoban.db"
    path.write_bytes(b"this is not sqlite" * 100)
    engine = create_sqlite_engine(path)

    with pytest.raises(ReplicaError, match="not a database"):
        SqlAdvisoryStore(engine).exploited_catalog_released()

    engine.dispose()


def test_an_unreadable_stored_release_time_is_a_replica_error(engine: Engine) -> None:
    store = SqlAdvisoryStore(engine)
    store.replace_exploited_catalog_if_newer(
        ExploitedCatalog("2026.10.29", RELEASED_29, (exploited("CVE-2024-21762"),)),
        synced_at=SYNCED,
    )
    with engine.begin() as connection:
        connection.execute(update(source_states).values(released_at="yesterday"))

    with pytest.raises(ReplicaError, match="公開日時が読めない"):
        store.exploited_catalog_released()
