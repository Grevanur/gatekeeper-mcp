"""Development-only human approver identities, kept separate from tool agents."""

from pathlib import Path

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, model_validator

from app.configuration import load_yaml_mapping


class ApproverIdentity(BaseModel):
    subject_id: str
    display_name: str
    role: str


class ApproversConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tokens: dict[str, str]
    approvers: dict[str, ApproverIdentity]

    @model_validator(mode="after")
    def validate_references(self) -> "ApproversConfiguration":
        unknown = set(self.tokens.values()) - set(self.approvers)
        if unknown:
            raise ValueError(f"Tokens reference unknown approvers: {sorted(unknown)}")
        return self


def load_approvers_configuration(path: Path | str) -> ApproversConfiguration:
    return ApproversConfiguration.model_validate(load_yaml_mapping(Path(path)))


class ApproverAuthenticator:
    def __init__(self, configuration: ApproversConfiguration) -> None:
        self._configuration = configuration

    def authenticate(self, token: str) -> ApproverIdentity | None:
        subject_id = self._configuration.tokens.get(token)
        return self._configuration.approvers.get(subject_id) if subject_id else None


approver_bearer_scheme = HTTPBearer(auto_error=False)


def get_current_approver(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(approver_bearer_scheme),
) -> ApproverIdentity:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")
    identity = request.app.state.approver_authenticator.authenticate(credentials.credentials)
    if identity is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid approver bearer token")
    return identity
