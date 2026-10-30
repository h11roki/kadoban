from datetime import datetime
from enum import StrEnum
from typing import Protocol

from app.domain.exploited import ExploitedCatalog


class AdvisorySourceError(Exception):
    pass


class ReplicaError(Exception):
    pass


class CatalogReplacement(StrEnum):
    REPLACED = "replaced"
    SAME_RELEASE = "same_release"
    OLDER_RELEASE = "older_release"


class ExploitedCatalogSource(Protocol):
    def fetch(self) -> ExploitedCatalog: ...


class ExploitedCatalogStore(Protocol):
    def replace_exploited_catalog_if_newer(
        self, catalog: ExploitedCatalog, synced_at: datetime
    ) -> CatalogReplacement: ...
