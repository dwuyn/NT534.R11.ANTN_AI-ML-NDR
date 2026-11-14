"""Wire contracts shared by the ML pipeline and future alert/LLM services."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


UtcDatetime = Annotated[datetime, AfterValidator(_ensure_utc)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Window(StrictModel):
    start: UtcDatetime
    end: UtcDatetime
    size_sec: int
    type: Literal["tumbling"] = "tumbling"


class Entity(StrictModel):
    type: Literal["host", "host_pair", "host_domain"] = "host"
    src_ip: str
    dst_ip: str | None = None
    dst_port: int | None = None
    proto: str | None = None
    domain: str | None = None


class FeatureSnapshot(StrictModel):
    snapshot_id: str
    schema_version: Literal["1.0"] = "1.0"
    feature_set_version: str
    window: Window
    entity: Entity
    features: dict[str, float]
    context: dict[str, Any] = Field(default_factory=dict)
    label: int | None = None


class ModelInfo(StrictModel):
    name: str
    version: str
    type: Literal["anomaly", "classification", "scorecard"]


class RuleInfo(StrictModel):
    id: str
    name: str
    version: str


class TopFeature(StrictModel):
    name: str
    value: float
    z: float
    shap: float | None = None


class DetectionEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    timestamp: UtcDatetime
    dataset: Literal["ndr.detections"] = "ndr.detections"
    module: Literal["ndr-ml"] = "ndr-ml"
    rule: RuleInfo
    model: ModelInfo
    score: float = Field(ge=0.0, le=1.0)
    threshold: float = Field(ge=0.0, le=1.0)
    is_alert: bool
    top_features: list[TopFeature]
    entity: Entity
    window: Window
    uids: list[str]
    snapshot_id: str


class Mitre(StrictModel):
    tactic: list[str] = Field(default_factory=list)
    technique: list[str] = Field(default_factory=list)


class ResponseRecommendation(StrictModel):
    recommended: str
    auto_action: str | None = None
    approval_required: bool = True


class AiSummary(StrictModel):
    summary: str
    model: str
    confidence: float | None = None
    evidence: list[str] = Field(default_factory=list)
    hypotheses: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    mitre: Mitre = Field(default_factory=Mitre)
    caveats: list[str] = Field(default_factory=list)


class AlertEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    timestamp: UtcDatetime
    first_seen: UtcDatetime | None = None
    last_seen: UtcDatetime | None = None
    alert_id: str
    status: Literal["open", "closed"] = "open"
    risk: int = Field(ge=0, le=100)
    level: Literal["low", "medium", "high", "critical"]
    count: int = Field(default=1, ge=1)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
    scenario: str | None = None
    entities: dict[str, str]
    evidence: dict[str, list[str]]
    mitre: Mitre = Field(default_factory=Mitre)
    response: ResponseRecommendation
    ai: AiSummary | None = None


class FeedbackLabel(StrictModel):
    binary: int | None = Field(default=None, ge=0, le=1)
    attack_type: str | None = None
    mitre_tactic: list[str] = Field(default_factory=list)
    mitre_technique: list[str] = Field(default_factory=list)


class FeedbackEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    timestamp: UtcDatetime
    alert_id: str
    analyst: str
    disposition: Literal["true_positive", "false_positive", "undetermined"]
    reason: str = ""
    actions: list[str] = Field(default_factory=list)
    notes: str = ""
    label: FeedbackLabel = Field(default_factory=FeedbackLabel)


class ModelMetadata(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    model_name: str
    version: str
    created_at: UtcDatetime
    stage: Literal["staging", "production", "archived"] = "staging"
    feature_set_version: str
    features: list[str]
    threshold: float
    normalization: dict[str, float]
    training: dict[str, Any]
    metrics: dict[str, float] = Field(default_factory=dict)
    owner: str = "team-ndr"


class GroundTruthRun(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: str
    scenario: str
    kind: Literal["benign", "attack"]
    variant: str
    start_ts: UtcDatetime
    end_ts: UtcDatetime
    attacker_ip: str | None = None
    victim_ip: str | None = None
    tool: str
    mitre_tactic: list[str] = Field(default_factory=list)
    mitre_technique: list[str] = Field(default_factory=list)
    expected_detection: list[str] = Field(default_factory=list)
    notes: str = ""
