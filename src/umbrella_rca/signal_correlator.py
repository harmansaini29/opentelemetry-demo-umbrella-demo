"""
Project UMBRELLA - OpenTelemetry Astronomy Shop Demo Integration
Production-Grade Multi-Signal Correlator & Competitive Hypothesis Engine
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from .schemas import TelemetrySnapshot, ErrorEvent, ImpactLevel, ActionRiskTier


class SignalAnalysisResult(BaseModel):
    signal_name: str
    weight: float
    confidence_contribution: float
    detected_anomalies: List[str] = Field(default_factory=list)
    raw_evidence: Dict[str, Any] = Field(default_factory=dict)


class HypothesisEvaluation(BaseModel):
    hypothesis_id: str
    name: str
    category: str
    source_component: str
    target_file: Optional[str] = None
    line_number: Optional[int] = None
    base_confidence: float = 0.0
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    penalty_score: float = 0.0
    net_confidence: float = 0.0
    impact_level: ImpactLevel = ImpactLevel.HIGH
    suggested_risk_tier: ActionRiskTier = ActionRiskTier.TIER_2_CONFIG_RESTART
    remediation_suggestion: str = ""
    next_safe_diagnostic_check: str = ""
    attack_classification: Optional[str] = None
    observed_symptoms: List[str] = Field(default_factory=list)
    contributing_factors: List[str] = Field(default_factory=list)
    unknowns: List[str] = Field(default_factory=list)


class CorrelationMatrix(BaseModel):
    signals: Dict[str, SignalAnalysisResult] = Field(default_factory=dict)
    aggregate_confidence: float = 0.0
    dominant_bottleneck: str = ""
    suggested_risk_tier: ActionRiskTier = ActionRiskTier.TIER_2_CONFIG_RESTART
    impact_level: ImpactLevel = ImpactLevel.HIGH
    ranked_hypotheses: List[HypothesisEvaluation] = Field(default_factory=list)
    temporal_ordering: Dict[str, Any] = Field(default_factory=dict)
    security_verdict: Dict[str, Any] = Field(default_factory=dict)


class SoftwareSignalCorrelator:
    """
    Evaluates competing hypotheses for the OpenTelemetry Astronomy Shop webstore
    using multi-signal evidence fusion, dual supporting/contradicting evidence,
    temporal ordering, and security threat detection.
    """

    @classmethod
    def evaluate(
        cls,
        errors: List[ErrorEvent],
        telemetry: Optional[TelemetrySnapshot],
        config_data: Dict[str, Any],
        rag_hits: List[Dict[str, Any]],
        call_chain_injections: Optional[List[str]] = None
    ) -> CorrelationMatrix:
        matrix = CorrelationMatrix()

        # ---------------------------------------------------------------------
        # 1. Base Signal Extraction
        # ---------------------------------------------------------------------
        sig1 = SignalAnalysisResult(signal_name="stack_trace_ast", weight=0.35, confidence_contribution=0.0)
        sig2 = SignalAnalysisResult(signal_name="telemetry_saturation", weight=0.30, confidence_contribution=0.0)
        sig3 = SignalAnalysisResult(signal_name="code_config_state", weight=0.20, confidence_contribution=0.0)
        sig4 = SignalAnalysisResult(signal_name="rag_knowledge_grounding", weight=0.15, confidence_contribution=0.0)

        combined_text = " ".join(
            (e.error_type + " " + e.error_message + " " + e.stack_trace) for e in errors
        ).lower()

        # Detect symptoms in errors
        has_timeout_err = any("timeout" in e.error_type.lower() or "timeout" in e.error_message.lower() for e in errors)
        has_queuepool_msg = "queuepool" in combined_text or ("pool" in combined_text and ("exhausted" in combined_text or "limit" in combined_text or "overflow" in combined_text))
        has_sqlite_lock_msg = "database is locked" in combined_text or ("sqlite" in combined_text and "lock" in combined_text) or ("operationalerror" in combined_text and "lock" in combined_text)
        has_jwt_msg = "jwt" in combined_text or "expired" in combined_text or "401" in combined_text or "unauthorized" in combined_text
        has_gateway_msg = "504" in combined_text or "gateway timeout" in combined_text or "aggregator unresponsive" in combined_text or "payment gateway timed out" in combined_text
        has_schema_msg = "422" in combined_text or "unprocessable" in combined_text or "schema" in combined_text or "validation" in combined_text

        # Signal 1 Population
        if has_queuepool_msg:
            sig1.detected_anomalies.append("Connection pool exhaustion in stack trace")
            sig1.confidence_contribution = sig1.weight * 0.95
        elif has_sqlite_lock_msg:
            sig1.detected_anomalies.append("SQLite exclusive lock timeout in stack trace")
            sig1.confidence_contribution = sig1.weight * 0.95
        elif has_jwt_msg:
            sig1.detected_anomalies.append("Authentication / token signature rejection in stack trace")
            sig1.confidence_contribution = sig1.weight * 0.95
        elif has_gateway_msg:
            sig1.detected_anomalies.append("Upstream gateway socket failure in stack trace")
            sig1.confidence_contribution = sig1.weight * 0.95
        elif has_schema_msg:
            sig1.detected_anomalies.append("Payload schema deserialization error in stack trace")
            sig1.confidence_contribution = sig1.weight * 0.95
        elif has_timeout_err:
            sig1.detected_anomalies.append("Generic concurrency / execution timeout in stack trace")
            sig1.confidence_contribution = sig1.weight * 0.70
        elif errors:
            sig1.detected_anomalies.append(f"Application exception: {errors[0].error_type}")
            sig1.confidence_contribution = sig1.weight * 0.50

        # Signal 2 Population (Telemetry)
        pool_util = telemetry.pool_utilization_pct if telemetry else 0.0
        active_conns = telemetry.active_connections if telemetry else 0
        pool_size_val = telemetry.pool_size if telemetry else 0
        p99_lat = telemetry.latency_p99_ms if telemetry else 0.0
        err_count_5m = telemetry.error_count_last_5m if telemetry else len(errors)

        if telemetry:
            sig2.raw_evidence = {
                "pool_utilization_pct": pool_util,
                "active_connections": active_conns,
                "pool_size": pool_size_val,
                "latency_p99_ms": p99_lat,
                "error_count_last_5m": err_count_5m
            }
            if pool_util >= 100.0 or (pool_size_val > 0 and active_conns >= pool_size_val):
                sig2.detected_anomalies.append(f"Connection pool saturated: {active_conns}/{pool_size_val} ({pool_util:.1f}%)")
                sig2.confidence_contribution = sig2.weight * 1.0
            elif p99_lat > 1000.0:
                sig2.detected_anomalies.append(f"Elevated P99 response latency: {p99_lat:.1f}ms")
                sig2.confidence_contribution = sig2.weight * 0.75
            elif err_count_5m > 0:
                sig2.detected_anomalies.append(f"Elevated error count: {err_count_5m} errors")
                sig2.confidence_contribution = sig2.weight * 0.60
            else:
                sig2.confidence_contribution = sig2.weight * 0.30
        else:
            sig2.confidence_contribution = sig2.weight * 0.20

        # Signal 3 Population (Config AST)
        pool_sz = config_data.get("POOL_SIZE", config_data.get("DB_POOL_SIZE", config_data.get("pool_size", None)))
        max_over = config_data.get("MAX_OVERFLOW", config_data.get("DB_MAX_OVERFLOW", config_data.get("max_overflow", None)))
        sig3.raw_evidence["configured_pool_size"] = pool_sz
        sig3.raw_evidence["configured_max_overflow"] = max_over

        try:
            pool_int = int(pool_sz) if pool_sz is not None else None
        except (ValueError, TypeError):
            pool_int = None

        error_claims_low_pool = any("size 2" in (e.error_message.lower() + e.error_type.lower()) or "size 5" in e.error_message.lower() for e in errors)
        if (pool_int is not None and pool_int <= 5) or error_claims_low_pool:
            effective_sz = pool_int if (pool_int is not None and pool_int <= 5) else 2
            sig3.detected_anomalies.append(f"Constrained pool configuration detected (pool_size={effective_sz})")
            sig3.confidence_contribution = sig3.weight * 1.0
        elif pool_int is not None:
            sig3.detected_anomalies.append(f"Configured pool capacity: {pool_int}")
            sig3.confidence_contribution = sig3.weight * 0.70
        else:
            sig3.confidence_contribution = sig3.weight * 0.40

        # Signal 4 Population (RAG)
        if rag_hits:
            top_hit = rag_hits[0]
            sig4.raw_evidence = {
                "top_file": top_hit.get("file_path", ""),
                "repository": top_hit.get("repository", ""),
                "rrf_score": top_hit.get("rrf_score", 0.0)
            }
            sig4.detected_anomalies.append(f"Grounded knowledge matched in {top_hit.get('repository', 'reference')}")
            sig4.confidence_contribution = sig4.weight * 0.90
        else:
            sig4.confidence_contribution = sig4.weight * 0.30

        matrix.signals = {
            "signal_1_ast": sig1,
            "signal_2_telemetry": sig2,
            "signal_3_config": sig3,
            "signal_4_rag": sig4
        }

        # ---------------------------------------------------------------------
        # 2. Competitive Hypothesis Scoring (Dual Evidence: Support vs Contradict)
        # ---------------------------------------------------------------------
        candidate_evaluations: List[HypothesisEvaluation] = []

        # ---------------------------------------------------------------------
        # Hypothesis A: Database Connection Pool Starvation
        # ---------------------------------------------------------------------
        hyp_pool = HypothesisEvaluation(
            hypothesis_id="HYP-POOL-STARVATION",
            name="Database connection pool starvation: Pool size and overflow capacity exhausted under concurrent inflow",
            category="RESOURCE_EXHAUSTION",
            source_component="database_pool",
            impact_level=ImpactLevel.CRITICAL,
            suggested_risk_tier=ActionRiskTier.TIER_2_CONFIG_RESTART,
            remediation_suggestion="Scale DB_POOL_SIZE / POOL_SIZE from constrained limit to sustainable capacity (10-20) and configure MAX_OVERFLOW, then trigger graceful connection pool refresh.",
            next_safe_diagnostic_check="Inspect engine.pool.status() and pool checkedout connection counters."
        )
        if has_queuepool_msg:
            hyp_pool.supporting_evidence.append("Stack trace explicitly reports QueuePool exhaustion limit breached")
            hyp_pool.base_confidence += 0.40
        elif has_timeout_err and not has_sqlite_lock_msg and not has_gateway_msg:
            hyp_pool.supporting_evidence.append("Timeout exception in database-access code frame")
            hyp_pool.base_confidence += 0.20

        if pool_util >= 100.0 or (pool_size_val > 0 and active_conns >= pool_size_val):
            hyp_pool.supporting_evidence.append(f"Telemetry proves pool saturation: {active_conns}/{pool_size_val} active ({pool_util:.1f}%)")
            hyp_pool.base_confidence += 0.30
        if (pool_int is not None and pool_int <= 5) or error_claims_low_pool:
            hyp_pool.supporting_evidence.append(f"Configuration AST confirms constrained pool capacity (size={pool_int or 2})")
            hyp_pool.base_confidence += 0.20
        if rag_hits and any("constants" in str(h.get("file_path", "")) or "pool" in str(h.get("symbol_name", "")) for h in rag_hits):
            hyp_pool.supporting_evidence.append("Curated RAG matches connection pool configuration constants")
            hyp_pool.base_confidence += 0.15

        # Contradicting Evidence (Penalties)
        if telemetry and pool_util < 50.0 and active_conns < pool_size_val and pool_size_val > 0:
            hyp_pool.contradicting_evidence.append(f"Telemetry refutes pool exhaustion: pool utilization is only {pool_util:.1f}% ({active_conns}/{pool_size_val} connections active)")
            hyp_pool.penalty_score += 0.45
        if has_sqlite_lock_msg:
            hyp_pool.contradicting_evidence.append("Error indicates SQLite table write lock contention rather than connection pool saturation")
            hyp_pool.penalty_score += 0.30
        if has_jwt_msg:
            hyp_pool.contradicting_evidence.append("Error originates in authentication middleware before database connection checkout")
            hyp_pool.penalty_score += 0.50
        if has_gateway_msg:
            hyp_pool.contradicting_evidence.append("Exception represents outbound 3rd-party HTTP socket failure, not database pool starvation")
            hyp_pool.penalty_score += 0.40
        if has_schema_msg:
            hyp_pool.contradicting_evidence.append("Error originates in payload schema validation before database connection checkout")
            hyp_pool.penalty_score += 0.50

        hyp_pool.net_confidence = round(min(0.99, max(0.05, hyp_pool.base_confidence - hyp_pool.penalty_score)), 4)
        candidate_evaluations.append(hyp_pool)

        # ---------------------------------------------------------------------
        # Hypothesis B: SQLite Exclusive Lock Contention
        # ---------------------------------------------------------------------
        hyp_lock = HypothesisEvaluation(
            hypothesis_id="HYP-DB-LOCK",
            name="Database lock contention: SQLite exclusive write lock timed out during concurrent transactions",
            category="LOCK_CONTENTION",
            source_component="database_storage",
            impact_level=ImpactLevel.HIGH,
            suggested_risk_tier=ActionRiskTier.TIER_2_CONFIG_RESTART,
            remediation_suggestion="Enable PRAGMA busy_timeout = 15000 and WAL (Write-Ahead Logging) journal mode in database connection settings.",
            next_safe_diagnostic_check="Execute read-only probe: Check PRAGMA journal_mode and PRAGMA busy_timeout on the database."
        )
        if has_sqlite_lock_msg:
            hyp_lock.supporting_evidence.append("Stack trace explicitly reports 'database is locked' / OperationalError")
            hyp_lock.base_confidence += 0.45
        if "sqlite" in str(config_data.get("DATABASE_URL", "")).lower() or "sqlite" in combined_text:
            hyp_lock.supporting_evidence.append("Database dialect is SQLite single-file storage with default rollback journal")
            hyp_lock.base_confidence += 0.25
        if rag_hits and any("data_connector" in str(h.get("file_path", "")) for h in rag_hits):
            hyp_lock.supporting_evidence.append("Curated RAG matches SQLite busy_timeout & PRAGMA configuration runbooks")
            hyp_lock.base_confidence += 0.15

        if has_jwt_msg:
            hyp_lock.contradicting_evidence.append("Incident occurred during token validation prior to database transaction")
            hyp_lock.penalty_score += 0.50
        if has_queuepool_msg and not has_sqlite_lock_msg:
            hyp_lock.contradicting_evidence.append("QueuePool capacity limit reached before database lock could be acquired")
            hyp_lock.penalty_score += 0.35

        hyp_lock.net_confidence = round(min(0.99, max(0.05, hyp_lock.base_confidence - hyp_lock.penalty_score)), 4)
        candidate_evaluations.append(hyp_lock)

        # ---------------------------------------------------------------------
        # Hypothesis C: Authentication Token Expiration / Cascade
        # ---------------------------------------------------------------------
        hyp_auth = HypothesisEvaluation(
            hypothesis_id="HYP-AUTH-CASCADE",
            name="Authentication failure: Expired or malformed bearer token presented to endpoint",
            category="AUTH_FAILURE",
            source_component="auth_middleware",
            impact_level=ImpactLevel.HIGH,
            suggested_risk_tier=ActionRiskTier.TIER_3_CODE_PATCH,
            remediation_suggestion="Configure JWT clock skew leeway tolerance (300s) and enable auto-refresh fallback in config.",
            next_safe_diagnostic_check="Inspect token expiration claims against local server clock and verify secret key rotation status."
        )
        if has_jwt_msg:
            hyp_auth.supporting_evidence.append("Exception explicitly matches HTTP 401 Unauthorized or ExpiredSignatureError")
            hyp_auth.base_confidence += 0.45
        if any("auth" in e.stack_trace.lower() or "jwt" in e.stack_trace.lower() for e in errors):
            hyp_auth.supporting_evidence.append("AST traceback traces into authentication verification middleware")
            hyp_auth.base_confidence += 0.30

        if has_queuepool_msg:
            hyp_auth.contradicting_evidence.append("Exception trace originates inside database connection pool rather than auth layer")
            hyp_auth.penalty_score += 0.45
        if has_sqlite_lock_msg:
            hyp_auth.contradicting_evidence.append("Incident stems from database table lock contention")
            hyp_auth.penalty_score += 0.45

        hyp_auth.net_confidence = round(min(0.99, max(0.05, hyp_auth.base_confidence - hyp_auth.penalty_score)), 4)
        candidate_evaluations.append(hyp_auth)

        # ---------------------------------------------------------------------
        # Hypothesis D: Upstream Gateway Timeout
        # ---------------------------------------------------------------------
        hyp_gateway = HypothesisEvaluation(
            hypothesis_id="HYP-GATEWAY-TIMEOUT",
            name="External upstream gateway timeout: 3rd-party payment aggregator socket timed out without backoff retry",
            category="GATEWAY_TIMEOUT",
            source_component="payment_gateway_client",
            impact_level=ImpactLevel.HIGH,
            suggested_risk_tier=ActionRiskTier.TIER_2_CONFIG_RESTART,
            remediation_suggestion="Increase socket timeout to 5.0s, configure 3 exponential retries, and arm circuit breaker in payment configuration.",
            next_safe_diagnostic_check="Send non-blocking ICMP ping and HTTP health check to external aggregator endpoint."
        )
        if has_gateway_msg:
            hyp_gateway.supporting_evidence.append("HTTP 504 Gateway Timeout or aggregator unresponsive reported")
            hyp_gateway.base_confidence += 0.45
        if p99_lat > 2000.0:
            hyp_gateway.supporting_evidence.append(f"High network latency ({p99_lat:.1f}ms) consistent with outbound socket hang")
            hyp_gateway.base_confidence += 0.25

        if has_queuepool_msg:
            hyp_gateway.contradicting_evidence.append("Error is internal QueuePool exhaustion, not external HTTP gateway failure")
            hyp_gateway.penalty_score += 0.45
        if has_jwt_msg:
            hyp_gateway.contradicting_evidence.append("Request was rejected at ingress due to missing or invalid bearer token")
            hyp_gateway.penalty_score += 0.45

        hyp_gateway.net_confidence = round(min(0.99, max(0.05, hyp_gateway.base_confidence - hyp_gateway.penalty_score)), 4)
        candidate_evaluations.append(hyp_gateway)

        # ---------------------------------------------------------------------
        # Hypothesis E: Payload Schema Validation Failure
        # ---------------------------------------------------------------------
        hyp_schema = HypothesisEvaluation(
            hypothesis_id="HYP-SCHEMA-VALIDATION",
            name="Payload schema validation failure: Malformed request body or uncoerced input fields rejected with 422",
            category="SCHEMA_VALIDATION",
            source_component="payload_validator",
            impact_level=ImpactLevel.MEDIUM,
            suggested_risk_tier=ActionRiskTier.TIER_2_CONFIG_RESTART,
            remediation_suggestion="Configure schema field default coercers and relaxed boundary sanitization in service config.",
            next_safe_diagnostic_check="Validate incoming JSON payload against Pydantic request model schema."
        )
        if has_schema_msg:
            hyp_schema.supporting_evidence.append("HTTP 422 Unprocessable Entity or schema validation mismatch caught")
            hyp_schema.base_confidence += 0.55

        if has_queuepool_msg or has_sqlite_lock_msg:
            hyp_schema.contradicting_evidence.append("Failure occurs during database operations well after schema deserialization")
            hyp_schema.penalty_score += 0.45

        hyp_schema.net_confidence = round(min(0.99, max(0.05, hyp_schema.base_confidence - hyp_schema.penalty_score)), 4)
        candidate_evaluations.append(hyp_schema)

        # ---------------------------------------------------------------------
        # Hypothesis F: Security Attack - Concurrency Flood / DDoS Burst
        # ---------------------------------------------------------------------
        hyp_attack_ddos = HypothesisEvaluation(
            hypothesis_id="HYP-ATTACK-DDOS",
            name="Security Anomaly: High-concurrency traffic surge exceeding baseline SLA capacity",
            category="ATTACK_DDOS",
            source_component="network_ingress",
            impact_level=ImpactLevel.CRITICAL,
            suggested_risk_tier=ActionRiskTier.TIER_2_CONFIG_RESTART,
            remediation_suggestion="Enforce rate limiting on ingress gateway (10 req/s per IP) and deploy Web Application Firewall (WAF) throttle rule.",
            next_safe_diagnostic_check="Inspect access logs for IP entropy and request burst rate from identical subnets.",
            attack_classification="TRAFFIC_SURGE_FLOOD"
        )
        if active_conns >= 10 or err_count_5m >= 8 or (telemetry and telemetry.pool_utilization_pct >= 250.0):
            hyp_attack_ddos.supporting_evidence.append(f"Abnormal concurrent surge: {active_conns} simultaneous transactions under {pool_util:.1f}% load")
            hyp_attack_ddos.base_confidence += 0.40
        if "surge" in combined_text or "burst" in combined_text or "flooded" in combined_text or "saturation" in combined_text:
            hyp_attack_ddos.supporting_evidence.append("Traffic burst and downstream flood detected in telemetry/logs")
            hyp_attack_ddos.base_confidence += 0.30
        if p99_lat > 2000.0 and active_conns >= 10:
            hyp_attack_ddos.supporting_evidence.append(f"Extreme P99 latency SLA degradation ({p99_lat:.1f}ms) under concurrency spike")
            hyp_attack_ddos.base_confidence += 0.20
        if has_queuepool_msg:
            hyp_attack_ddos.supporting_evidence.append("Rapid resource exhaustion symptomatic of unthrottled concurrent burst")
            hyp_attack_ddos.base_confidence += 0.15

        if not has_timeout_err and not has_queuepool_msg and err_count_5m < 3 and active_conns < 10:
            hyp_attack_ddos.contradicting_evidence.append("Traffic volume is within nominal operating boundaries")
            hyp_attack_ddos.penalty_score += 0.50

        hyp_attack_ddos.net_confidence = round(min(0.95, max(0.05, hyp_attack_ddos.base_confidence - hyp_attack_ddos.penalty_score)), 4)
        candidate_evaluations.append(hyp_attack_ddos)

        # ---------------------------------------------------------------------
        # Hypothesis G: Security Attack - Credential Stuffing / Auth Flood
        # ---------------------------------------------------------------------
        hyp_attack_auth = HypothesisEvaluation(
            hypothesis_id="HYP-ATTACK-AUTH",
            name="Security Attack: Credential stuffing or token brute-force attack detected",
            category="ATTACK_BRUTE_FORCE",
            source_component="auth_middleware",
            impact_level=ImpactLevel.HIGH,
            suggested_risk_tier=ActionRiskTier.TIER_2_CONFIG_RESTART,
            remediation_suggestion="Trigger IP ban for repeated failed authentications and engage adaptive captcha challenge.",
            next_safe_diagnostic_check="Audit authentication failure rate per IP address over the last 15 minutes.",
            attack_classification="CREDENTIAL_BRUTE_FORCE"
        )
        if has_jwt_msg:
            if err_count_5m >= 5:
                hyp_attack_auth.supporting_evidence.append(f"Repetitive authentication rejections ({err_count_5m} failures in last 5m) symptomatic of credential stuffing")
                hyp_attack_auth.base_confidence += 0.85
                # When repeated auth failures are high, penalize benign single token expiration
                hyp_auth.contradicting_evidence.append(f"High frequency of auth rejections ({err_count_5m} in 5m) indicates automated brute-force attack rather than single expired token")
                hyp_auth.penalty_score += 0.35
                hyp_auth.net_confidence = round(min(0.99, max(0.05, hyp_auth.base_confidence - hyp_auth.penalty_score)), 4)
            else:
                hyp_attack_auth.supporting_evidence.append("Authentication error observed")
                hyp_attack_auth.base_confidence += 0.30
        else:
            hyp_attack_auth.contradicting_evidence.append("No authentication rejection signatures in incident error stream")
            hyp_attack_auth.penalty_score += 0.60

        hyp_attack_auth.net_confidence = round(min(0.95, max(0.05, hyp_attack_auth.base_confidence - hyp_attack_auth.penalty_score)), 4)
        candidate_evaluations.append(hyp_attack_auth)

        # ---------------------------------------------------------------------
        # Hypothesis H: SQL Injection Attempt
        # ---------------------------------------------------------------------
        if call_chain_injections:
            hyp_sqli = HypothesisEvaluation(
                hypothesis_id="HYP-ATTACK-SQLI",
                name="Security Attack: SQL Injection signature detected in query parameters",
                category="ATTACK_SQLI",
                source_component="database_input_sanitizer",
                impact_level=ImpactLevel.CRITICAL,
                suggested_risk_tier=ActionRiskTier.TIER_3_CODE_PATCH,
                remediation_suggestion="Enforce parameterized SQL prepared statements and activate SQL injection firewall filter.",
                next_safe_diagnostic_check="Inspect raw query strings in query log for tautology or UNION keywords.",
                attack_classification="SQL_INJECTION",
                base_confidence=0.55
            )
            for inj in call_chain_injections:
                hyp_sqli.supporting_evidence.append(f"Detected signature: {inj}")
                hyp_sqli.base_confidence += 0.25
            hyp_sqli.net_confidence = round(min(0.95, max(0.10, hyp_sqli.base_confidence)), 4)
            candidate_evaluations.append(hyp_sqli)

            # Penalize operational lock and pool starvation when malicious SQL injection is active
            hyp_lock.contradicting_evidence.append("Malicious SQL injection pattern detected in input payload")
            hyp_lock.penalty_score += 0.40
            hyp_lock.net_confidence = round(min(0.99, max(0.05, hyp_lock.base_confidence - hyp_lock.penalty_score)), 4)

        # ---------------------------------------------------------------------
        # 3. Rank Competing Hypotheses by Net Confidence (Descending)
        # ---------------------------------------------------------------------
        candidate_evaluations.sort(key=lambda h: h.net_confidence, reverse=True)
        matrix.ranked_hypotheses = candidate_evaluations

        top_hyp = candidate_evaluations[0]
        matrix.dominant_bottleneck = top_hyp.name
        matrix.impact_level = top_hyp.impact_level
        matrix.suggested_risk_tier = top_hyp.suggested_risk_tier
        matrix.aggregate_confidence = top_hyp.net_confidence

        # ---------------------------------------------------------------------
        # 4. Temporal Ordering Analysis (T0 -> T4 Timeline Reconstruction)
        # ---------------------------------------------------------------------
        matrix.temporal_ordering = {
            "t0_trigger": "Traffic inflow arrived at Astronomy Shop webstore endpoint",
            "t1_saturation": f"Resource utilization peaked at {pool_util:.1f}%" if pool_util > 0 else "Telemetry steady",
            "t2_bottleneck": f"Bottleneck reached in {top_hyp.source_component}",
            "t3_symptom": f"Exception raised: {errors[0].error_type if errors else 'Unknown'}",
            "t4_observation": "Incident intercepted by OpenTelemetry Collector and ingested into UMBRELLA Agent 1"
        }

        # ---------------------------------------------------------------------
        # 5. Security Verdict
        # ---------------------------------------------------------------------
        active_attacks = [h for h in candidate_evaluations if h.attack_classification and h.net_confidence >= 0.50]
        if active_attacks:
            matrix.security_verdict = {
                "verdict": "SECURITY_ATTACK_DETECTED",
                "threat_level": "HIGH" if any(a.impact_level == ImpactLevel.CRITICAL for a in active_attacks) else "MEDIUM",
                "attack_types": [a.attack_classification for a in active_attacks],
                "recommended_action": active_attacks[0].remediation_suggestion
            }
        else:
            matrix.security_verdict = {
                "verdict": "BENIGN_OPERATIONAL_FAULT",
                "threat_level": "NONE",
                "details": "Failure consistent with organic concurrency saturation or configuration constraint"
            }

        return matrix
