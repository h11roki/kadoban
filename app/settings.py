from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KADOBAN_", env_ignore_empty=True)

    data_dir: Path = REPOSITORY_ROOT / "data"
    http_timeout_seconds: Annotated[float, Field(gt=0)] = 60

    @field_validator("data_dir")
    @classmethod
    def absolute(cls, data_dir: Path) -> Path:
        return data_dir.resolve()

    @property
    def database_path(self) -> Path:
        return self.data_dir / "kadoban.db"

    @property
    def nvd_feed_dir(self) -> Path:
        return self.data_dir / "nvd"
