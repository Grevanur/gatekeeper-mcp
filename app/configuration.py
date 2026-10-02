"""Validated loading for security configuration files."""

from pathlib import Path
from typing import Any

import yaml


class ConfigurationError(ValueError):
    """Raised when a required security configuration file is malformed."""


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    """Load a YAML mapping or fail closed with a clear configuration error."""

    try:
        loaded = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as error:
        raise ConfigurationError(f"Unable to load configuration: {path}") from error

    if not isinstance(loaded, dict):
        raise ConfigurationError(f"Configuration must be a YAML mapping: {path}")
    return loaded

