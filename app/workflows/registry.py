"""Configuration-backed workflow registry and conservative normalization."""

from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from app.configuration import load_yaml_mapping
from app.workflows.models import (
    BusinessCriticality,
    ContextSource,
    ResolvedWorkflowContext,
    WorkflowContextInput,
    WorkflowDefinition,
    WorkflowRegistryConfiguration,
)


class UnknownWorkflowError(ValueError):
    pass


class WorkflowContextResolver:
    _criticality_order = {
        BusinessCriticality.LOW: 0,
        BusinessCriticality.MEDIUM: 1,
        BusinessCriticality.HIGH: 2,
        BusinessCriticality.CRITICAL: 3,
    }

    def __init__(self, configuration: WorkflowRegistryConfiguration) -> None:
        self._workflows = {workflow.id: workflow for workflow in configuration.workflows}

    @classmethod
    def from_config_file(cls, path: Path | str) -> "WorkflowContextResolver":
        return cls(WorkflowRegistryConfiguration.model_validate(load_yaml_mapping(Path(path))))

    def resolve(
        self,
        *,
        gateway_environment: str,
        declared: WorkflowContextInput | None = None,
        now: datetime | None = None,
    ) -> ResolvedWorkflowContext:
        declared = declared or WorkflowContextInput()
        workflow = self._lookup(declared.workflow_id)
        conflicts: list[str] = []
        if declared.environment is not None and declared.environment != gateway_environment:
            conflicts.append("environment")

        criticality = self._maximum_criticality(
            workflow.business_criticality if workflow else BusinessCriticality.LOW,
            declared.business_criticality or BusinessCriticality.LOW,
        )
        if workflow and declared.business_criticality and declared.business_criticality != workflow.business_criticality:
            conflicts.append("business_criticality")
        if workflow and declared.customer_impact is False and workflow.customer_impact:
            conflicts.append("customer_impact")

        # Time derived from the registered workflow is trusted.  A caller can
        # flag additional urgency, but cannot claim an after-hours change is in-hours.
        after_hours = bool(declared.after_hours) or self._is_after_hours(workflow, now)
        return ResolvedWorkflowContext(
            workflow_id=workflow.id if workflow else None,
            environment=gateway_environment,
            business_criticality=criticality,
            customer_impact=bool((workflow and workflow.customer_impact) or declared.customer_impact),
            estimated_records_affected=declared.estimated_records_affected or 0,
            after_hours=bool(after_hours),
            # Emergency is deliberately risk-increasing only; it never bypasses policy.
            emergency=bool(declared.emergency),
            tags=sorted(set((workflow.tags if workflow else []) + declared.tags)),
            sources={
                "environment": ContextSource.GATEWAY_DERIVED,
                "workflow": ContextSource.WORKFLOW_REGISTRY if workflow else ContextSource.CALLER_DECLARED,
                "business_criticality": ContextSource.WORKFLOW_REGISTRY if workflow else ContextSource.CALLER_DECLARED,
            },
            conflicts=sorted(set(conflicts)),
        )

    def _lookup(self, workflow_id: str | None) -> WorkflowDefinition | None:
        if workflow_id is None:
            return None
        workflow = self._workflows.get(workflow_id)
        if workflow is None:
            raise UnknownWorkflowError(f"Unknown workflow: {workflow_id}")
        return workflow

    def _maximum_criticality(
        self, first: BusinessCriticality, second: BusinessCriticality
    ) -> BusinessCriticality:
        return max((first, second), key=lambda value: self._criticality_order[value])

    @staticmethod
    def _is_after_hours(workflow: WorkflowDefinition | None, now: datetime | None) -> bool:
        if workflow is None:
            return False
        current = (now or datetime.now(tz=ZoneInfo(workflow.time_zone))).astimezone(ZoneInfo(workflow.time_zone))
        return current.weekday() >= 5 or not (workflow.workday_start_hour <= current.hour < workflow.workday_end_hour)
