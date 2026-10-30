from datetime import UTC, datetime
from functools import partial

import httpx
import typer
from pydantic import ValidationError

from app.application.ports import (
    AdvisorySourceError,
    CatalogReplacement,
    NvdSyncKind,
    ReplicaError,
)
from app.application.sync_exploited import SyncExploited
from app.application.sync_nvd import NvdFeedSyncResult, SyncNvd
from app.infrastructure.db.advisory_store import SqlAdvisoryStore
from app.infrastructure.db.engine import create_sqlite_engine
from app.infrastructure.kev import CisaKevCatalog
from app.infrastructure.nvd_feeds import NvdFeedFiles
from app.settings import Settings

USER_AGENT = "kadoban (+https://github.com/h11roki/kadoban)"

app = typer.Typer(no_args_is_help=True)
advisories = typer.Typer(no_args_is_help=True, help="脆弱性情報を手元に写す")
app.add_typer(advisories, name="advisories")


def echo_nvd_feed(result: NvdFeedSyncResult) -> None:
    typer.echo(f"NVD {result.name}: {result.read:,} 件を読み、{result.written:,} 件を書いた")


@advisories.command("sync", help="CISA KEV と NVD を取り込む")
def sync_advisories() -> None:
    try:
        settings = Settings()
    except ValidationError as error:
        typer.echo(f"KADOBAN_ で始まる環境変数の値が正しくない: {error}", err=True)
        raise typer.Exit(1) from error
    now = partial(datetime.now, UTC)
    source_failed = False
    try:
        engine = create_sqlite_engine(settings.database_path)
        store = SqlAdvisoryStore(engine)
        try:
            with httpx.Client(
                timeout=settings.http_timeout_seconds,
                headers={"User-Agent": USER_AGENT},
                follow_redirects=True,
            ) as client:
                try:
                    kev = SyncExploited(CisaKevCatalog(client), store, now=now).run()
                except AdvisorySourceError as error:
                    typer.echo(str(error), err=True)
                    source_failed = True
                else:
                    match kev.replacement:
                        case CatalogReplacement.REPLACED:
                            typer.echo(f"KEV: 版 {kev.version} の {kev.count:,} 件に入れ替えた")
                        case CatalogReplacement.SAME_RELEASE:
                            typer.echo(f"KEV: 版 {kev.version} は取り込み済み")
                        case CatalogReplacement.OLDER_RELEASE:
                            typer.echo(
                                f"KEV: 取れた版 {kev.version} は手元より古いので入れ替えなかった"
                            )
                feeds = NvdFeedFiles(client, settings.nvd_feed_dir, this_year=now().year)
                try:
                    nvd = SyncNvd(feeds, store, now=now, on_feed=echo_nvd_feed).run()
                except AdvisorySourceError as error:
                    typer.echo(str(error), err=True)
                    source_failed = True
                else:
                    scope = "全件" if nvd.kind is NvdSyncKind.ALL else "直近 8 日の更新分"
                    typer.echo(f"NVD: {scope}を取り込んだ")
        finally:
            engine.dispose()
    except ReplicaError as error:
        typer.echo(
            f"{error}\n`uv run alembic upgrade head` を流したか、"
            "ほかの取り込みが動いていないか確かめる",
            err=True,
        )
        raise typer.Exit(1) from error
    if source_failed:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
