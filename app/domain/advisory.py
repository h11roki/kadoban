from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class NvdRange:
    vendor: str
    product: str
    version: str
    start_including: str | None
    start_excluding: str | None
    end_including: str | None
    end_excluding: str | None
    conditional: bool


@dataclass(frozen=True)
class CnaRange:
    vendor: str | None
    product: str | None
    package_name: str | None
    default_status: str | None
    version: str | None
    status: str | None
    less_than: str | None
    less_than_or_equal: str | None
    version_type: str | None


@dataclass(frozen=True)
class Advisory:
    cve_id: str
    published: datetime
    last_modified: datetime
    status: str
    nvd_ranges: tuple[NvdRange, ...]
    cna_ranges: tuple[CnaRange, ...]

    def __post_init__(self) -> None:
        if self.published.tzinfo is None or self.last_modified.tzinfo is None:
            raise ValueError(f"{self.cve_id} の公表日時と更新日時にはタイムゾーンが要る")
