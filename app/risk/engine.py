"""Explainable, configuration-driven risk assessment."""

from pathlib import Path

from app.configuration import load_yaml_mapping
from app.risk.models import (
    RiskAssessment,
    RiskConfiguration,
    RiskFactor,
    RiskLevel,
)
from app.security.models import ToolRequestContext


class RiskEngine:
    def __init__(self, configuration: RiskConfiguration) -> None:
        self._configuration = configuration

    @classmethod
    def from_config_file(cls, path: Path | str) -> "RiskEngine":
        configuration = RiskConfiguration.model_validate(load_yaml_mapping(Path(path)))
        return cls(configuration)

    def assess(self, context: ToolRequestContext) -> RiskAssessment:
        tool_risk = self._configuration.tool_risk
        is_unknown_tool = context.tool_name not in tool_risk or context.tool_name == "default_unknown_tool"
        baseline = tool_risk.get(context.tool_name, tool_risk["default_unknown_tool"])
        factors = [RiskFactor(name="base_tool_risk", value=baseline)]
        modifiers = self._configuration.risk_modifiers

        if is_unknown_tool:
            factors.append(RiskFactor(name="unknown_tool", value=modifiers.unknown_tool))
        if context.is_external_destination:
            factors.append(
                RiskFactor(name="external_destination", value=modifiers.external_destination)
            )
        if context.sensitive_data_involved:
            factors.append(RiskFactor(name="sensitive_data", value=modifiers.sensitive_data))
        if context.agent.environment == "production":
            factors.append(
                RiskFactor(name="production_environment", value=modifiers.production_environment)
            )
        if context.is_write_operation:
            factors.append(RiskFactor(name="write_operation", value=modifiers.write_operation))

        score = min(100, sum(factor.value for factor in factors))
        return RiskAssessment(score=score, level=self._level_for_score(score), factors=factors)

    @staticmethod
    def _level_for_score(score: int) -> RiskLevel:
        if score <= 30:
            return RiskLevel.LOW
        if score <= 60:
            return RiskLevel.MEDIUM
        if score <= 80:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL

