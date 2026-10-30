from datetime import UTC, datetime

import httpx
import typer

from app.application.ports import AdvisorySourceError, ReplicaError
from app.application.sync_exploited import ExploitedSyncOutcome, SyncExploited
from app.infrastructure.db.advisory_store import SqlAdvisoryStore
from app.infrastructure.db.engine import create_sqlite_engine
from app.infrastructure.kev import CisaKevCatalog
from app.settings import Settings

USER_AGENT = "kadoban (+https://github.com/h11roki/kadoban)"

app = typer.Typer(no_args_is_help=True)
advisories = typer.Typer(no_args_is_help=True, help="脆弱性情報を手元に写す")
app.add_typer(advisories, name="advisories")


@advisories.command("sync", help="CISA KEV を取り込む")
def sync_advisories() -> None:
    settings = Settings()
    engine = create_sqlite_engine(settings.database_path)
    try:
        with httpx.Client(
            timeout=settings.http_timeout_seconds,
            headers={"User-Agent": USER_AGENT},
            follow_redirects=True,
        ) as client:
            result = SyncExploited(
                CisaKevCatalog(client), SqlAdvisoryStore(engine), now=lambda: datetime.now(UTC)
            ).run()
    except AdvisorySourceError as error:
        typer.echo(f"KEV を取り込めなかった: {error}", err=True)
        raise typer.Exit(1) from error
    except ReplicaError as error:
        typer.echo(
            f"{error}\n`uv run alembic upgrade head` を流したか、"
            "ほかの取り込みが動いていないか確かめる",
            err=True,
        )
        raise typer.Exit(1) from error
    finally:
        engine.dispose()
    match result.outcome:
        case ExploitedSyncOutcome.REPLACED:
            typer.echo(f"KEV: 版 {result.version} の {result.count:,} 件に入れ替えた")
        case ExploitedSyncOutcome.UNCHANGED:
            typer.echo(f"KEV: 版 {result.version} は取り込み済み")
        case ExploitedSyncOutcome.OLDER_THAN_STORED:
            typer.echo(f"KEV: 取れた版 {result.version} は手元より古いので入れ替えなかった")


if __name__ == "__main__":
    app()
