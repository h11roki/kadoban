from pathlib import Path
from sqlite3 import Connection as SqliteConnection

from sqlalchemy import Connection, Engine, create_engine, event


def create_sqlite_engine(path: Path) -> Engine:
    path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{path}")
    event.listen(engine, "connect", _leave_transactions_to_sqlalchemy)
    event.listen(engine, "begin", _take_the_write_lock_first)
    return engine


def _leave_transactions_to_sqlalchemy(dbapi_connection: SqliteConnection, _: object) -> None:
    dbapi_connection.isolation_level = None


def _take_the_write_lock_first(connection: Connection) -> None:
    connection.exec_driver_sql("BEGIN IMMEDIATE")
