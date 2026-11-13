"""
Project UMBRELLA - OpenTelemetry Astronomy Shop Demo Integration
Agent 1: Production-Grade Root Cause & Diagnostic Analyzer (RCA) Engine
"""

import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from .schemas import (
    IncidentContext,
    RCAResult,
    RootCause,
    ImpactLevel,
    ActionRiskTier,
    ErrorEvent,
    TelemetrySnapshot
)
from .ast_inspector import ASTInspector, CallChainAnalysis
from .signal_correlator import SoftwareSignalCorrelator, HypothesisEvaluation


class RootCauseAnalyzer:
    """
    Agent 1 in the UMBRELLA Council integrated with OpenTelemetry Astronomy Shop.
    Performs autonomous, multi-signal diagnosis across competing hypotheses with
    explicit supporting/contradicting evidence penalties, temporal ordering (T0-T4),
    and security attack detection.
    """

    def __init__(self, rag_engine=None):
        self._rag_engine = rag_engine

    def diagnose(self, incident: IncidentContext) -> RCAResult:
        """
        Executes an evidence-driven, multi-signal diagnosis on an Astronomy Shop incident.
        """
        # Step 1: Call-Chain & AST Inspection
        target_file_path = None
        failing_line = None
        call_chain_injections: List[str] = []
        call_chain_analysis: Optional[CallChainAnalysis] = None

        if incident.errors:
            primary_err = incident.errors[0]
            if primary_err.target_file and (os.path.exists(primary_err.target_file) or os.path.exists(os.path.join(os.getcwd(), primary_err.target_file))):
                target_file_path = primary_err.target_file
                failing_line = primary_err.line_number

            if primary_err.stack_trace:
                frames = ASTInspector.parse_stack_trace(primary_err.stack_trace)
                if frames:
                    raw_context = (primary_err.stack_trace or "") + " " + (primary_err.error_message or "")
                    call_chain_analysis = ASTInspector.inspect_call_chain(frames, raw_text=raw_context)
                    if call_chain_analysis.suspicious_injection_patterns:
                        call_chain_injections = call_chain_analysis.suspicious_injection_patterns

                    if not target_file_path:
                        if call_chain_analysis.deepest_failing_frame:
                            target_file_path = call_chain_analysis.deepest_failing_frame.file_path
                            failing_line = call_chain_analysis.deepest_failing_frame.line_number
                        elif frames:
                            target_file_path = frames[-1].file_path
                            failing_line = frames[-1].line_number

            if not target_file_path and primary_err.target_file:
                target_file_path = primary_err.target_file
                failing_line = primary_err.line_number

        # Step 2: Extract target service config state via AST
        config_data: Dict[str, Any] = {}
        candidate_configs = []
        if incident.config_file and os.path.exists(incident.config_file):
            candidate_configs.append(incident.config_file)

        # Microservice specific config paths
        srv_name = incident.service_name.lower()
        if "checkout" in srv_name:
            candidate_configs.append(os.path.join(os.getcwd(), "src", "checkout", "flags.json"))
        elif "payment" in srv_name:
            candidate_configs.append(os.path.join(os.getcwd(), "src", "payment", "package.json"))
        elif "product" in srv_name or "catalog" in srv_name:
            candidate_configs.append(os.path.join(os.getcwd(), "src", "product-catalog", "flags.json"))

        for cfg_path in candidate_configs:
            if os.path.exists(cfg_path):
                if cfg_path.endswith(".py"):
                    try:
                        import ast
                        with open(cfg_path, "r", encoding="utf-8") as f:
                            tree = ast.parse(f.read(), filename=cfg_path)
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Assign):
                                for target in node.targets:
                                    if isinstance(target, ast.Name):
                                        config_data[target.id] = ASTInspector._get_literal_value(node.value)
                        if not target_file_path:
                            target_file_path = cfg_path
                        break
                    except Exception:
                        pass
                elif cfg_path.endswith(".json"):
                    try:
                        import json
                        with open(cfg_path, "r", encoding="utf-8") as f:
                            config_data.update(json.load(f))
                    except Exception:
                        pass

        # Step 3: RAG Grounding Hooks
        rag_hits: List[Dict[str, Any]] = []
        if self._rag_engine and incident.errors:
            err_msg = f"{incident.errors[0].error_type} {incident.errors[0].error_message}"
            try:
                hits = self._rag_engine.retrieve(query_text=err_msg, top_k=3)
                rag_hits = [
                    {
                        "file_path": h.chunk.file_path,
                        "repository": h.chunk.repository,
                        "symbol_name": h.chunk.symbol_name,
                        "rrf_score": h.rrf_score
                    }
                    for h in hits
                ]
            except Exception:
                pass

        # Step 4: Multi-Signal Competitive Hypothesis Correlation
        matrix = SoftwareSignalCorrelator.evaluate(
            errors=incident.errors,
            telemetry=incident.telemetry,
            config_data=config_data,
            rag_hits=rag_hits,
            call_chain_injections=call_chain_injections
        )

        # Step 5: Convert Ranked Hypotheses to RootCause Schemas
        pool_sz = config_data.get("POOL_SIZE", config_data.get("DB_POOL_SIZE", 5))
        max_over = config_data.get("MAX_OVERFLOW", config_data.get("DB_MAX_OVERFLOW", 0))

        converted_causes: List[RootCause] = []
        for idx, hyp in enumerate(matrix.ranked_hypotheses):
            rank = idx + 1
            if hyp.hypothesis_id == "HYP-POOL-STARVATION":
                cause_text = f"Database connection pool starvation: Pool size ({pool_sz}) and overflow ({max_over}) exhausted under concurrent load."
                comp_source = f"{incident.service_name}.database_pool"
            elif hyp.hypothesis_id == "HYP-DB-LOCK":
                cause_text = "Database lock contention: SQLite Exclusive Lock write timeout during concurrent bookings."
                comp_source = f"{incident.service_name}.database_storage"
            elif hyp.hypothesis_id == "HYP-AUTH-CASCADE":
                cause_text = "Authentication failure: Expired or malformed bearer token presented to endpoint."
                comp_source = f"{incident.service_name}.auth_middleware"
            elif hyp.hypothesis_id == "HYP-GATEWAY-TIMEOUT":
                cause_text = "External Upstream Gateway Timeout: 3rd-party payment aggregator socket timed out without backoff retry."
                comp_source = f"{incident.service_name}.payment_gateway_client"
            elif hyp.hypothesis_id == "HYP-SCHEMA-VALIDATION":
                cause_text = "Payload Schema Validation failure: Malformed request body or uncoerced input fields rejected with 422."
                comp_source = f"{incident.service_name}.payload_validator"
            else:
                cause_text = hyp.name
                comp_source = f"{incident.service_name}.{hyp.source_component}"

            supporting_sig_dict: Dict[str, Any] = {
                "hypothesis_id": hyp.hypothesis_id,
                "hypothesis_rank": rank,
                "failing_exception": incident.errors[0].error_type if incident.errors else "TimeoutError",
                "error_message": incident.errors[0].error_message if incident.errors else "",
                "ast_inspected_file": target_file_path,
                "active_connections_peak": incident.telemetry.active_connections if incident.telemetry else 5,
                "pool_utilization_pct": incident.telemetry.pool_utilization_pct if incident.telemetry else 250.0,
                "configured_pool_size": pool_sz,
                "configured_max_overflow": max_over,
                "supporting_evidence_count": len(hyp.supporting_evidence),
                "contradicting_evidence_count": len(hyp.contradicting_evidence)
            }

            cause_file = target_file_path
            cause_line = failing_line

            cause_obj = RootCause(
                cause=cause_text,
                confidence=hyp.net_confidence,
                impact_level=hyp.impact_level,
                supporting_signals=supporting_sig_dict,
                source_component=comp_source,
                target_file=cause_file,
                line_number=cause_line,
                remediation_suggestion=hyp.remediation_suggestion,
                hypothesis_id=hyp.hypothesis_id,
                hypothesis_rank=rank,
                supporting_evidence=hyp.supporting_evidence,
                contradicting_evidence=hyp.contradicting_evidence,
                observed_symptoms=[f"Error: {e.error_type} - {e.error_message}" for e in incident.errors[:3]],
                contributing_factors=[
                    f"Pool size={pool_sz}",
                    f"Max overflow={max_over}",
                    f"Utilization={incident.telemetry.pool_utilization_pct:.1f}%" if incident.telemetry else "No telemetry"
                ],
                unknowns=["Downstream socket queue depth"] if not incident.telemetry else [],
                next_safe_diagnostic_check=hyp.next_safe_diagnostic_check,
                attack_classification=hyp.attack_classification
            )
            converted_causes.append(cause_obj)

        # Primary causes: Top-ranked hypothesis and significant runners-up
        primary_causes = [converted_causes[0]]
        for c in converted_causes[1:]:
            if c.confidence >= 0.40 and len(primary_causes) < 3:
                primary_causes.append(c)

        top_cause = primary_causes[0]

        exec_summary = (
            f"DIAGNOSIS FOR {incident.service_name.upper()} (Incident: {incident.incident_id}): "
            f"Rank-1 Cause: {top_cause.cause} [Confidence: {top_cause.confidence:.1%}]. "
            f"Impact Level: {top_cause.impact_level.value.upper()}. "
            f"Security Verdict: {matrix.security_verdict.get('verdict', 'BENIGN')}. "
            f"Evaluated {len(converted_causes)} competing hypotheses."
        )

        tech_details = (
            f"AST Code Pointer: {target_file_path}:{failing_line or 'N/A'}\n"
            f"Top Hypothesis: {top_cause.hypothesis_id} (Score: {top_cause.confidence:.4f})\n"
            f"Supporting Evidence ({len(top_cause.supporting_evidence)}): {'; '.join(top_cause.supporting_evidence)}\n"
            f"Contradicting Evidence ({len(top_cause.contradicting_evidence)}): {'; '.join(top_cause.contradicting_evidence) or 'None'}\n"
            f"Next Safe Diagnostic Check: {top_cause.next_safe_diagnostic_check}\n"
            f"Signals Breakdown: AST={matrix.signals['signal_1_ast'].confidence_contribution:.3f}, "
            f"Telemetry={matrix.signals['signal_2_telemetry'].confidence_contribution:.3f}, "
            f"Config={matrix.signals['signal_3_config'].confidence_contribution:.3f}, "
            f"RAG={matrix.signals['signal_4_rag'].confidence_contribution:.3f}"
        )

        return RCAResult(
            incident_id=incident.incident_id,
            analysis_timestamp=datetime.now(timezone.utc),
            primary_causes=primary_causes,
            overall_confidence=top_cause.confidence,
            executive_summary=exec_summary,
            technical_details=tech_details,
            correlated_signals={
                name: {
                    "weight": sig.weight,
                    "confidence_contribution": sig.confidence_contribution,
                    "anomalies": sig.detected_anomalies,
                    "evidence": sig.raw_evidence
                }
                for name, sig in matrix.signals.items()
            },
            suggested_risk_tier=matrix.suggested_risk_tier,
            competing_hypotheses=converted_causes,
            temporal_ordering=matrix.temporal_ordering,
            security_verdict=matrix.security_verdict
        )
