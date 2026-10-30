from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine

from app.infrastructure.db.engine import create_sqlite_engine

ROOT = Path(__file__).resolve().parents[2]


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
