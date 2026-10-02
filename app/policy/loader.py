"""Policy configuration loading from a required YAML file."""

from pathlib import Path

from app.configuration import load_yaml_mapping
from app.policy.models import PoliciesConfiguration


def load_policies_configuration(path: Path | str) -> PoliciesConfiguration:
    return PoliciesConfiguration.model_validate(load_yaml_mapping(Path(path)))

