from pathlib import Path
from typing import Annotated

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KADOBAN_", env_ignore_empty=True)

    data_dir: Path = REPOSITORY_ROOT / "data"
    http_timeout_seconds: Annotated[float, Field(gt=0)] = 60

    @property
    def database_path(self) -> Path:
        return self.data_dir / "kadoban.db"

    @property
    def nvd_feed_dir(self) -> Path:
        return self.data_dir.resolve() / "nvd"
