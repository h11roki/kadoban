from datetime import datetime
from typing import Protocol

from app.domain.exploited import ExploitedCatalog


class AdvisorySourceError(Exception):
    pass


class ExploitedCatalogSource(Protocol):
    def fetch(self) -> ExploitedCatalog: ...


class ExploitedCatalogStore(Protocol):
    def exploited_catalog_version(self) -> str | None: ...

    def replace_exploited_catalog(self, catalog: ExploitedCatalog, synced_at: datetime) -> None: ...
