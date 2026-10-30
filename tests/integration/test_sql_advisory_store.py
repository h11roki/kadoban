from collections.abc import Iterator
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, select, update

from app.application.ports import CatalogReplacement, ReplicaError
from app.domain.exploited import ExploitedCatalog, ExploitedVulnerability
from app.infrastructure.db.advisory_store import SqlAdvisoryStore
from app.infrastructure.db.engine import create_sqlite_engine
from app.infrastructure.db.tables import exploited_vulnerabilities, source_states

ROOT = Path(__file__).resolve().parents[2]
RELEASED_28 = datetime(2026, 10, 28, 19, 0, tzinfo=UTC)
RELEASED_29 = datetime(2026, 10, 29, 19, 9, 34, 400300, tzinfo=UTC)
SYNCED = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)


def exploited(cve_id: str) -> ExploitedVulnerability:
    return ExploitedVulnerability(
        cve_id=cve_id,
        date_added=date(2024, 2, 9),
        due_date=date(2024, 2, 16),
        used_by_ransomware=True,
        required_action="Apply mitigations per vendor instructions.",
    )


def catalog(released: datetime, *cve_ids: str) -> ExploitedCatalog:
    return ExploitedCatalog(released.date().isoformat(), released, tuple(map(exploited, cve_ids)))


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


def stored(engine: Engine) -> tuple[list[str], str | None]:
    with engine.connect() as connection:
        cve_ids = list(connection.scalars(select(exploited_vulnerabilities.c.cve_id)))
        released = connection.scalar(select(source_states.c.released_at))
    return cve_ids, released


def test_the_first_catalog_fills_an_empty_store(engine: Engine) -> None:
    replacement = SqlAdvisoryStore(engine).replace_exploited_catalog_if_newer(
        catalog(RELEASED_29, "CVE-2024-21762"), synced_at=SYNCED
    )

    assert replacement is CatalogReplacement.REPLACED
    assert stored(engine) == (["CVE-2024-21762"], RELEASED_29.isoformat(timespec="microseconds"))


def test_a_newer_catalog_drops_entries_that_left_it(engine: Engine) -> None:
    store = SqlAdvisoryStore(engine)
    store.replace_exploited_catalog_if_newer(
        catalog(RELEASED_28, "CVE-2024-21762", "CVE-1"), synced_at=SYNCED
    )

    replacement = store.replace_exploited_catalog_if_newer(
        catalog(RELEASED_29, "CVE-2024-21762"), synced_at=SYNCED
    )

    assert replacement is CatalogReplacement.REPLACED
    assert stored(engine)[0] == ["CVE-2024-21762"]


@pytest.mark.parametrize(
    ("released", "expected"),
    [
        (RELEASED_29, CatalogReplacement.SAME_RELEASE),
        (RELEASED_28, CatalogReplacement.OLDER_RELEASE),
    ],
)
def test_a_catalog_not_newer_than_the_stored_one_is_not_written(
    engine: Engine, released: datetime, expected: CatalogReplacement
) -> None:
    store = SqlAdvisoryStore(engine)
    store.replace_exploited_catalog_if_newer(
        catalog(RELEASED_29, "CVE-2024-21762"), synced_at=SYNCED
    )

    replacement = store.replace_exploited_catalog_if_newer(
        catalog(released, "CVE-1"), synced_at=SYNCED
    )

    assert replacement is expected
    assert stored(engine) == (["CVE-2024-21762"], RELEASED_29.isoformat(timespec="microseconds"))


@pytest.mark.parametrize(
    ("stored_text", "message"),
    [("yesterday", "読めない"), ("2026-10-29T19:09:34", "タイムゾーンが無い")],
)
def test_an_unusable_stored_release_time_is_a_replica_error(
    engine: Engine, stored_text: str, message: str
) -> None:
    store = SqlAdvisoryStore(engine)
    store.replace_exploited_catalog_if_newer(
        catalog(RELEASED_28, "CVE-2024-21762"), synced_at=SYNCED
    )
    with engine.begin() as connection:
        connection.execute(update(source_states).values(released_at=stored_text))

    with pytest.raises(ReplicaError, match=message):
        store.replace_exploited_catalog_if_newer(catalog(RELEASED_29, "CVE-1"), synced_at=SYNCED)

    assert stored(engine)[0] == ["CVE-2024-21762"]


def test_a_database_without_the_migration_is_a_replica_error(tmp_path: Path) -> None:
    engine = create_sqlite_engine(tmp_path / "unmigrated.db")

    with pytest.raises(ReplicaError, match="no such table"):
        SqlAdvisoryStore(engine).replace_exploited_catalog_if_newer(
            catalog(RELEASED_29, "CVE-1"), synced_at=SYNCED
        )

    engine.dispose()


def test_a_file_that_is_not_a_database_is_a_replica_error(tmp_path: Path) -> None:
    path = tmp_path / "kadoban.db"
    path.write_bytes(b"this is not sqlite" * 100)
    engine = create_sqlite_engine(path)

    with pytest.raises(ReplicaError, match="not a database"):
        SqlAdvisoryStore(engine).replace_exploited_catalog_if_newer(
            catalog(RELEASED_29, "CVE-1"), synced_at=SYNCED
        )

    engine.dispose()


def test_a_data_directory_that_cannot_be_made_is_a_replica_error(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("")

    with pytest.raises(ReplicaError, match="作れない"):
        create_sqlite_engine(blocker / "data" / "kadoban.db")
