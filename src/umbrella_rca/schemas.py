"""
Project UMBRELLA - OpenTelemetry Astronomy Shop Demo Integration
Unified Schemas & Data Contracts for Agent 1 (Root Cause Analyzer)
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class ImpactLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionRiskTier(str, Enum):
    TIER_1_SAFE_READONLY = "tier_1_safe_readonly"        # Metrics fetch, logs inspect, read-only
    TIER_2_CONFIG_RESTART = "tier_2_config_restart"      # Pool resize, safe service reload, cache clear
    TIER_3_CODE_PATCH = "tier_3_code_patch"              # AST code modification, git branch commit
    TIER_4_SCHEMA_DESTRUCTIVE = "tier_4_destructive"     # DB migration, table drop, dangerous op


class TelemetrySnapshot(BaseModel):
    service_name: str = Field(..., description="Target service identifier (e.g., checkoutservice, paymentservice)")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    active_connections: int = Field(default=0)
    pool_size: int = Field(default=0)
    pool_overflow: int = Field(default=0)
    pool_utilization_pct: float = Field(default=0.0)
    latency_p99_ms: float = Field(default=0.0)
    cpu_percent: float = Field(default=0.0)
    memory_mb: float = Field(default=0.0)
    error_count_last_5m: int = Field(default=0)
    custom_metrics: Dict[str, Any] = Field(default_factory=dict)


class ErrorEvent(BaseModel):
    event_id: str = Field(..., description="Unique event identifier")
    service_name: str = Field(..., description="Failing service")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error_type: str = Field(..., description="Exception class, e.g. 'TimeoutError', 'HTTP 504'")
    error_message: str = Field(..., description="Exception message text")
    stack_trace: str = Field(default="", description="Full traceback, gRPC status, or log snippet")
    target_file: Optional[str] = Field(default=None, description="Failing source file path")
    line_number: Optional[int] = Field(default=None, description="Failing line number")
    function_name: Optional[str] = Field(default=None, description="Failing function name")


class IncidentContext(BaseModel):
    incident_id: str = Field(..., description="Unique incident UUID")
    title: str = Field(..., description="Human-readable incident summary")
    service_name: str = Field(..., description="Primary service affected (e.g. checkoutservice, paymentservice)")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    telemetry: Optional[TelemetrySnapshot] = Field(default=None)
    errors: List[ErrorEvent] = Field(default_factory=list)
    environment: str = Field(default="opentelemetry-demo")
    raw_logs: Optional[str] = Field(default=None)
    repo_path: Optional[str] = Field(default=None, description="Root repository path of affected microservice")
    config_file: Optional[str] = Field(default=None, description="Path to active configuration file")


class RootCause(BaseModel):
    cause: str = Field(..., description="Concise statement of the root cause")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Mathematical confidence score")
    impact_level: ImpactLevel = Field(default=ImpactLevel.HIGH)
    supporting_signals: Dict[str, Any] = Field(
        default_factory=dict,
        description="Empirical evidence proving this diagnosis (metrics, logs, AST checks)"
    )
    source_component: str = Field(..., description="Module/component responsible, e.g. 'paymentservice.gateway'")
    target_file: Optional[str] = Field(default=None, description="File path requiring remediation")
    line_number: Optional[int] = Field(default=None)
    remediation_suggestion: str = Field(..., description="Recommended fix strategy")

    # Production-grade evidence & hypothesis fields
    hypothesis_id: str = Field(default="HYP-001", description="Unique hypothesis identifier")
    hypothesis_rank: int = Field(default=1, description="Rank among competing hypotheses (1 = Top-1)")
    supporting_evidence: List[str] = Field(default_factory=list, description="Explicit signals supporting this cause")
    contradicting_evidence: List[str] = Field(default_factory=list, description="Explicit signals refuting or weakening this cause")
    observed_symptoms: List[str] = Field(default_factory=list, description="Outward symptoms observed")
    contributing_factors: List[str] = Field(default_factory=list, description="Environmental conditions exacerbating failure")
    unknowns: List[str] = Field(default_factory=list, description="Unverified parameters or missing telemetry")
    next_safe_diagnostic_check: Optional[str] = Field(default=None, description="Recommended read-only verification probe")
    attack_classification: Optional[str] = Field(default=None, description="Classification if security attack detected")


class RCAResult(BaseModel):
    incident_id: str = Field(..., description="Associated incident ID")
    analysis_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    primary_causes: List[RootCause] = Field(..., description="Ranked list of identified root causes")
    overall_confidence: float = Field(..., ge=0.0, le=1.0)
    executive_summary: str = Field(..., description="Operator-friendly executive diagnosis")
    technical_details: str = Field(..., description="Deep technical explanation and stack analysis")
    correlated_signals: Dict[str, Any] = Field(
        default_factory=dict,
        description="Correlation breakdown across 4 software signals"
    )
    suggested_risk_tier: ActionRiskTier = Field(default=ActionRiskTier.TIER_2_CONFIG_RESTART)

    # Production-grade competing hypothesis & temporal fields
    competing_hypotheses: List[RootCause] = Field(default_factory=list, description="Full ranked set of competing hypotheses")
    temporal_ordering: Dict[str, Any] = Field(default_factory=dict, description="Timeline sequence of events")
    security_verdict: Dict[str, Any] = Field(default_factory=dict, description="Security anomaly and attack diagnosis")
