from pathlib import Path
from sqlite3 import Connection as SqliteConnection

from sqlalchemy import URL, Connection, Engine, create_engine, event

from app.application.ports import ReplicaError

TAKE_WRITE_LOCK = "take_write_lock"
BUSY_TIMEOUT_SECONDS = 30
MIGRATION_HINT = (
    "`uv run alembic upgrade head` を流したか、ほかの取り込みが長く書いていないか確かめる"
)


def create_sqlite_engine(path: Path) -> Engine:
    absolute = path.resolve()
    try:
        absolute.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ReplicaError(f"手元の DB の置き場 {absolute.parent} を作れない: {error}") from error
    engine = create_engine(
        URL.create("sqlite", database=str(absolute)),
        connect_args={"timeout": BUSY_TIMEOUT_SECONDS},
    )
    event.listen(engine, "connect", _leave_transactions_to_sqlalchemy)
    event.listen(engine, "begin", _begin)
    return engine


def _leave_transactions_to_sqlalchemy(dbapi_connection: SqliteConnection, _: object) -> None:
    dbapi_connection.isolation_level = None


def _begin(connection: Connection) -> None:
    if connection.get_execution_options().get(TAKE_WRITE_LOCK, False):
        connection.exec_driver_sql("BEGIN IMMEDIATE")
    else:
        connection.exec_driver_sql("BEGIN")
