"""Validated, configuration-driven approval workflow definitions."""

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.configuration import load_yaml_mapping


class ApprovalStage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    roles: list[str] = Field(min_length=1)
    timeout_seconds: int = Field(gt=0)


class BreakGlassConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    roles: list[str] = Field(default_factory=list)
    ttl_seconds: int = Field(default=300, gt=0)
    require_reason: bool = True

    @model_validator(mode="after")
    def require_roles_when_enabled(self) -> "BreakGlassConfiguration":
        if self.enabled and not self.roles:
            raise ValueError("Enabled break-glass configuration requires roles.")
        return self


class ApprovalWorkflow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str
    primary: ApprovalStage
    fallback: ApprovalStage | None = None
    final_timeout_action: Literal["DENY"] = "DENY"
    break_glass: BreakGlassConfiguration = Field(default_factory=BreakGlassConfiguration)


class ApprovalWorkflowsConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_workflows: dict[str, ApprovalWorkflow] = Field(min_length=1)


class ApprovalWorkflowRegistry:
    def __init__(self, configuration: ApprovalWorkflowsConfiguration) -> None:
        self._workflows = configuration.approval_workflows

    @classmethod
    def from_config_file(cls, path: Path | str) -> "ApprovalWorkflowRegistry":
        return cls(ApprovalWorkflowsConfiguration.model_validate(load_yaml_mapping(Path(path))))

    def get(self, workflow_id: str) -> ApprovalWorkflow:
        try:
            return self._workflows[workflow_id]
        except KeyError as error:
            raise ValueError(f"Unknown approval workflow: {workflow_id}") from error

    def validate_references(self, workflow_ids: set[str]) -> None:
        unknown = workflow_ids - set(self._workflows)
        if unknown:
            raise ValueError(f"Policies reference unknown approval workflows: {sorted(unknown)}")
