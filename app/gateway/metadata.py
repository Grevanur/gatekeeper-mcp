"""Configuration-backed security metadata for executable gateway tools."""

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from app.configuration import load_yaml_mapping


class ToolSecurityMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_category: str
    write_operation: bool = False
    external_destination: bool = False
    data_classification: str
    destructive: bool = False
    output_classification: str = "internal"
    sensitive_categories: list[str] = Field(default_factory=list)


class ToolMetadataConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tools: dict[str, ToolSecurityMetadata] = Field(min_length=1)


class ToolMetadataRegistry:
    def __init__(self, configuration: ToolMetadataConfiguration) -> None:
        self._tools = configuration.tools

    @classmethod
    def from_config_file(cls, path: Path | str) -> "ToolMetadataRegistry":
        configuration = ToolMetadataConfiguration.model_validate(load_yaml_mapping(Path(path)))
        return cls(configuration)

    def get(self, gateway_tool_name: str) -> ToolSecurityMetadata | None:
        """Return metadata only for explicitly configured executable tools."""

        return self._tools.get(gateway_tool_name)
