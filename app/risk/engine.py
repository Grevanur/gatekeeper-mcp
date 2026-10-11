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
        if context.session_sensitive_data_accessed:
            factors.append(
                RiskFactor(name="recent_sensitive_access", value=modifiers.recent_sensitive_access)
            )
        if context.session_sensitive_data_accessed and context.is_external_destination:
            factors.append(
                RiskFactor(
                    name="sensitive_to_external_transition",
                    value=modifiers.sensitive_to_external_transition,
                )
            )
        if context.agent.environment == "production":
            factors.append(
                RiskFactor(name="production_environment", value=modifiers.production_environment)
            )
        if context.is_write_operation:
            factors.append(RiskFactor(name="write_operation", value=modifiers.write_operation))
        workflow = context.workflow_context
        if workflow is not None:
            if workflow.business_criticality.value == "high":
                factors.append(RiskFactor(name="high_business_criticality", value=modifiers.high_business_criticality))
            if workflow.business_criticality.value == "critical":
                factors.append(RiskFactor(name="critical_business_criticality", value=modifiers.critical_business_criticality))
            if workflow.customer_impact:
                factors.append(RiskFactor(name="customer_impact", value=modifiers.customer_impact))
            if workflow.estimated_records_affected >= self._configuration.large_records_threshold:
                factors.append(RiskFactor(name="large_blast_radius", value=modifiers.large_blast_radius))
            elif workflow.estimated_records_affected >= self._configuration.bulk_records_threshold:
                factors.append(RiskFactor(name="bulk_blast_radius", value=modifiers.bulk_blast_radius))
            if workflow.after_hours:
                factors.append(RiskFactor(name="after_hours", value=modifiers.after_hours))
            if workflow.emergency:
                factors.append(RiskFactor(name="emergency_change", value=modifiers.emergency_change))

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
