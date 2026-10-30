from logging.config import fileConfig
from pathlib import Path

from alembic import context

from app.infrastructure.db.engine import create_sqlite_engine
from app.infrastructure.db.tables import metadata
from app.settings import Settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

database_path: Path = config.attributes.get("database_path") or Settings().database_path

if context.is_offline_mode():
    context.configure(
        url=f"sqlite:///{database_path}",
        target_metadata=metadata,
        literal_binds=True,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = create_sqlite_engine(database_path)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()
