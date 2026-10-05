"""Application configuration loaded from environment variables."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """Runtime settings for the gateway foundation."""

    app_name: str = "MCP Zero-Trust Gateway"
    environment: str = "development"
    database_url: str = "sqlite:///./data/gateway.db"
    config_directory: Path = Path("config")
    downstream_timeout_seconds: float = Field(default=10.0, gt=0)
    approval_ttl_seconds: int = Field(default=300, gt=0)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="MCP_GATEWAY_",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide, immutable settings instance."""

    return Settings()
