from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="RDC_", extra="ignore")

    env: Literal["development", "test", "staging", "production"] = "development"
    database_url: str = "postgresql+asyncpg://rdc:rdc@localhost:5432/rdc"
    redis_url: str = "redis://localhost:6379/0"
    s3_endpoint: str = "http://localhost:9000"
    s3_bucket: str = "rdc-local"
    s3_access_key: str = "rdc_local"
    s3_secret_key: str = "rdc_local_only_change_me"


@lru_cache
def get_settings() -> Settings:
    return Settings()
