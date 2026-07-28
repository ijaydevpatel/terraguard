"""Shared record types. Every module in the pipeline speaks in these objects."""
from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    NON_SECURITY = "non_security"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    INDETERMINATE = "indeterminate"


class EvidenceSource(str, Enum):
    TERRAFORM_PLAN_JSON = "terraform_plan_json"
    REPOSITORY = "repository"
    WORKFLOW = "workflow"
    BACKEND_CONFIG = "backend_config"
    AWS_API = "aws_api"


class ChangeAction(str, Enum):
    NO_OP = "no-op"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REPLACE = "replace"
    READ = "read"


class NormalisedEvent(str, Enum):
    """The security meaning of a raw diff. Phase 2 populates this."""

    PUBLIC_NETWORK_ACCESS = "restricted_to_public_network_access"
    PRIVILEGE_EXPANSION = "privilege_expansion"
    ENCRYPTION_DISABLED = "encryption_disabled"
    SECURITY_LOGGING_DISABLED = "security_logging_disabled"
    OUT_OF_BAND_DELETION = "out_of_band_deletion"
    OPERATIONAL_DRIFT = "non_security_operational_drift"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    INSECURE_STATE_HANDLING = "insecure_state_handling"


class AttributeChange(BaseModel):
    path: str
    before_category: str | None = None
    after_category: str | None = None
    before_redacted: str | None = None
    after_redacted: str | None = None
    sensitive: bool = False


class DriftRecord(BaseModel):
    """One entry derived from resource_drift or resource_changes in the plan JSON."""

    resource_address: str
    resource_type: str
    provider_name: str | None = None
    change_action: ChangeAction
    is_remote_drift: bool
    changed_attributes: list[AttributeChange] = Field(default_factory=list)


class Finding(BaseModel):
    """The single currency of the pipeline. Scanners and the drift path both emit these."""

    finding_id: str
    scenario_id: str | None = None
    evidence_source: EvidenceSource
    resource_type: str | None = None
    resource_address: str | None = None
    changed_attribute: str | None = None
    normalised_event: NormalisedEvent | None = None
    detail: str = ""
    control_id: str | None = None
    policy_status: PolicyStatus | None = None
    deterministic_severity: Severity | None = None
    lr_severity: Severity | None = None
    rf_severity: Severity | None = None
    model_confidence: float | None = None
    explanation: str = ""
    remediation: str = ""
    processing_time_ms: float | None = None
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    raw: dict[str, Any] = Field(default_factory=dict)


class EvidenceBundle(BaseModel):
    """Everything one run collected. Paths point at sanitised artefacts only."""

    run_id: str
    scenario_id: str | None = None
    terraform_dir: str
    plan_json_path: str | None = None
    plan_json_sanitised_path: str | None = None
    repository_files: list[str] = Field(default_factory=list)
    workflow_files: list[str] = Field(default_factory=list)
    backend_config_raw: str | None = None
    terraform_version: str | None = None
    commands_run: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: float | None = None
