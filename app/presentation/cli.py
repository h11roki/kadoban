from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from functools import partial
from typing import Annotated

import httpx
import typer
from pydantic import ValidationError
from sqlalchemy import Engine

from app.application.list_products import ListProducts
from app.application.ports import (
    AdvisorySourceError,
    CatalogReplacement,
    ConfigurationError,
    InvalidRequest,
    NvdSyncKind,
    ReplicaError,
)
from app.application.rebuild_product_index import RebuildProductIndex
from app.application.register_product import RegisterProduct
from app.application.search_products import SearchProducts
from app.application.sync_exploited import SyncExploited
from app.application.sync_nvd import NvdFeedSyncResult, SyncNvd
from app.domain.product import NameKey, Product, ProductRole
from app.infrastructure.aliases import load_aliases
from app.infrastructure.db.advisory_store import SqlAdvisoryStore
from app.infrastructure.db.engine import create_sqlite_engine
from app.infrastructure.db.product_store import SqlProductLedger, SqlProductNameIndex
from app.infrastructure.kev import CisaKevCatalog
from app.infrastructure.nvd_feeds import NvdFeedFiles
from app.infrastructure.sync_lock import exclusive_sync
from app.settings import Settings

USER_AGENT = "kadoban (+https://github.com/h11roki/kadoban)"
ROLE_LABELS = {
    ProductRole.VPN: "VPN 機器",
    ProductRole.SERVER: "サーバ",
    ProductRole.BUSINESS_SOFTWARE: "業務ソフト",
    ProductRole.FACTORY: "工場の機器",
    ProductRole.OTHER: "その他",
}

app = typer.Typer(no_args_is_help=True)
advisories = typer.Typer(no_args_is_help=True, help="脆弱性情報を手元に写す")
products = typer.Typer(no_args_is_help=True, help="使っている製品の台帳")
app.add_typer(advisories, name="advisories")
app.add_typer(products, name="product")


def load_settings() -> Settings:
    try:
        return Settings()
    except ValidationError as error:
        typer.echo(f"KADOBAN_ で始まる環境変数の値が正しくない: {error}", err=True)
        raise typer.Exit(1) from error


@contextmanager
def replica(settings: Settings) -> Iterator[Engine]:
    engine = create_sqlite_engine(settings.database_path)
    try:
        yield engine
    finally:
        engine.dispose()


def echo_error(error: Exception) -> None:
    typer.echo("\n".join([str(error), *getattr(error, "__notes__", [])]), err=True)


def fail(error: Exception) -> typer.Exit:
    echo_error(error)
    return typer.Exit(1)


def echo_nvd_feed(result: NvdFeedSyncResult) -> None:
    typer.echo(f"NVD {result.name}: {result.read:,} 件を読み、{result.written:,} 件を書いた")
    if result.unreadable:
        examples = ", ".join(record.cve_id or "ID 不明" for record in result.unreadable[:5])
        typer.echo(
            f"NVD {result.name}: {len(result.unreadable):,} 件は形が読めず飛ばした"
            f"({examples} など)。最初の理由: {result.unreadable[0].reason}",
            err=True,
        )


@advisories.command("sync", help="CISA KEV と NVD を取り込む")
def sync_advisories() -> None:
    settings = load_settings()
    now = partial(datetime.now, UTC)
    source_failed = False
    try:
        with ExitStack() as resources:
            resources.enter_context(exclusive_sync(settings.data_dir))
            engine = resources.enter_context(replica(settings))
            client = resources.enter_context(
                httpx.Client(
                    timeout=settings.http_timeout_seconds,
                    headers={"User-Agent": USER_AGENT},
                    follow_redirects=True,
                )
            )
            store = SqlAdvisoryStore(engine)
            try:
                kev = SyncExploited(CisaKevCatalog(client), store, now=now).run()
            except AdvisorySourceError as error:
                echo_error(error)
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
                nvd_kind = SyncNvd(feeds, store, now=now, on_feed=echo_nvd_feed).run()
            except AdvisorySourceError as error:
                echo_error(error)
                source_failed = True
            else:
                scope = "全件" if nvd_kind is NvdSyncKind.ALL else "直近 8 日の更新分"
                typer.echo(f"NVD: {scope}を取り込んだ")
    except ReplicaError as error:
        raise fail(error) from error
    if source_failed:
        raise typer.Exit(1)


@products.command("search", help="呼び名から、台帳に載せる名前の鍵の候補を探す")
def search_products(
    call: Annotated[str, typer.Argument(help="FortiGate、ヤマハ RTX830 など")],
) -> None:
    settings = load_settings()
    try:
        with replica(settings) as engine:
            candidates = SearchProducts(SqlProductNameIndex(engine), load_aliases()).run(call)
    except (ConfigurationError, InvalidRequest, ReplicaError) as error:
        raise fail(error) from error
    if not candidates:
        typer.echo("候補が無い。呼び名を短くするか、英語の製品名で探す")
        return
    for number, candidate in enumerate(candidates, start=1):
        origin = (
            "別名表" if candidate.from_alias else " / ".join(candidate.spellings[1:3]) or "索引"
        )
        typer.echo(f"{number}. {candidate.label}  CVE 延べ {candidate.cve_count:,}  ({origin})")
        typer.echo("   " + " ".join(f"--key {key}" for key in candidate.keys))


@products.command("add", help="使っている製品を台帳に載せる")
def add_product(
    company: Annotated[str, typer.Option(help="会社")],
    label: Annotated[str, typer.Option(help="呼び名。本社の FortiGate など")],
    key: Annotated[list[str], typer.Option(help="名前の鍵。product search の --key を写す")],
    version: Annotated[str | None, typer.Option(help="版。分からなければ書かない")] = None,
    role: Annotated[ProductRole, typer.Option(help="用途")] = ProductRole.OTHER,
    maintainer: Annotated[str | None, typer.Option(help="保守ベンダー")] = None,
) -> None:
    settings = load_settings()
    try:
        product = Product(
            company=company,
            label=label,
            keys=tuple(NameKey.parse(text) for text in key),
            version=version or None,
            role=role,
            maintainer=maintainer or None,
        )
    except ValueError as error:
        raise fail(error) from error
    try:
        with replica(settings) as engine:
            product_id = RegisterProduct(
                SqlProductNameIndex(engine),
                SqlProductLedger(engine),
                now=partial(datetime.now, UTC),
            ).run(product)
    except (InvalidRequest, ReplicaError) as error:
        raise fail(error) from error
    typer.echo(f"{product.company} の {product.label} を {product_id} 番で台帳に載せた")


@products.command("reindex", help="写した脆弱性情報から、製品名の索引を作り直す")
def reindex_products() -> None:
    settings = load_settings()
    try:
        with exclusive_sync(settings.data_dir), replica(settings) as engine:
            RebuildProductIndex(SqlAdvisoryStore(engine)).run()
    except ReplicaError as error:
        raise fail(error) from error
    typer.echo("製品名の索引を作り直した")


@products.command("list", help="会社の製品台帳を出す")
def list_products(company: Annotated[str, typer.Option(help="会社")]) -> None:
    settings = load_settings()
    try:
        with replica(settings) as engine:
            registered = ListProducts(SqlProductLedger(engine)).run(company)
    except ReplicaError as error:
        raise fail(error) from error
    if not registered:
        typer.echo(f"{company} の台帳はまだ空")
        return
    for entry in registered:
        product = entry.product
        typer.echo(
            f"{entry.id}. {product.label}  版 {product.version or '不明'}  "
            f"{ROLE_LABELS[product.role]}  保守 {product.maintainer or 'なし'}"
        )
        typer.echo("   " + ", ".join(map(str, product.keys)))


if __name__ == "__main__":
    app()
