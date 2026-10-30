from datetime import datetime
from typing import Protocol

from app.domain.exploited import ExploitedCatalog


class AdvisorySourceError(Exception):
    pass


class ReplicaError(Exception):
    pass


class ExploitedCatalogSource(Protocol):
    def fetch(self) -> ExploitedCatalog: ...


class ExploitedCatalogStore(Protocol):
    def exploited_catalog_released(self) -> datetime | None: ...

    def replace_exploited_catalog_if_newer(
        self, catalog: ExploitedCatalog, synced_at: datetime
    ) -> bool: ...
