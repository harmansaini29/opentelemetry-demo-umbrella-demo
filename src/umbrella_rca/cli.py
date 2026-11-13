"""
Project UMBRELLA - OpenTelemetry Astronomy Shop Demo Integration
Real-Time Diagnostic CLI & Evaluator for Agent 1 (RCA)
"""

import sys
import json
import argparse
from typing import Dict, Any

from .analyzer import RootCauseAnalyzer
from .scenarios import AstronomyShopIncidentSimulator
from .schemas import RCAResult


def format_rca_output(result: RCAResult) -> str:
    """Formats an RCAResult into a human-readable diagnostic report."""
    lines = []
    lines.append("=" * 80)
    lines.append(f" UMBRELLA AGENT 1 (RCA) DIAGNOSTIC REPORT: {result.incident_id}")
    lines.append("=" * 80)
    lines.append(f"Analysis Time : {result.analysis_timestamp.isoformat()}")
    lines.append(f"Confidence    : {result.overall_confidence:.1%}")
    lines.append(f"Risk Tier     : {result.suggested_risk_tier.value}")
    lines.append(f"Summary       : {result.executive_summary}")
    lines.append("-" * 80)

    # Security Verdict
    sec = result.security_verdict
    lines.append(f"[SECURITY THREAT VERDICT]: {sec.get('verdict')} (Threat Level: {sec.get('threat_level', 'NONE')})")
    if sec.get("attack_types"):
        lines.append(f"  Attack Types       : {', '.join(sec.get('attack_types'))}")
        lines.append(f"  Recommended Action : {sec.get('recommended_action')}")
    lines.append("-" * 80)

    # Temporal Sequence
    t_seq = result.temporal_ordering
    lines.append("[TEMPORAL EVENT ORDERING (T0 -> T4)]:")
    lines.append(f"  T0 (Trigger)     : {t_seq.get('t0_trigger')}")
    lines.append(f"  T1 (Saturation)  : {t_seq.get('t1_saturation')}")
    lines.append(f"  T2 (Bottleneck)  : {t_seq.get('t2_bottleneck')}")
    lines.append(f"  T3 (Symptom)     : {t_seq.get('t3_symptom')}")
    lines.append(f"  T4 (Observation) : {t_seq.get('t4_observation')}")
    lines.append("-" * 80)

    # Competing Hypotheses Ranking
    lines.append("[COMPETING HYPOTHESES RANKING]:")
    for hyp in result.competing_hypotheses:
        prefix = ">>> [TOP-1 CAUSE]" if hyp.hypothesis_rank == 1 else f"    [Rank {hyp.hypothesis_rank}]"
        lines.append(f"{prefix} {hyp.hypothesis_id}: {hyp.cause} (Net Confidence: {hyp.confidence:.1%})")
        lines.append(f"      Source Component: {hyp.source_component}")
        if hyp.supporting_evidence:
            lines.append("      + Supporting Evidence:")
            for s in hyp.supporting_evidence:
                lines.append(f"        * {s}")
        if hyp.contradicting_evidence:
            lines.append("      - Contradicting Evidence (Penalties):")
            for c in hyp.contradicting_evidence:
                lines.append(f"        * {c}")
        if hyp.next_safe_diagnostic_check:
            lines.append(f"      Safe Check Probe: {hyp.next_safe_diagnostic_check}")
        lines.append(f"      Remediation: {hyp.remediation_suggestion}")
        lines.append("")

    lines.append("=" * 80)
    return "\n".join(lines)


def run_all_scenarios():
    """Runs all real-time incident scenarios through Agent 1 and outputs results."""
    analyzer = RootCauseAnalyzer()
    scenarios = AstronomyShopIncidentSimulator.get_all_scenarios()

    print(f"\n[UMBRELLA-OTEL] Commencing live real-time evaluation across {len(scenarios)} incident scenarios...\n")

    summary_table = []

    for name, incident in scenarios.items():
        print(f"\n>>> Running Scenario: '{name}' on service '{incident.service_name}'...")
        res = analyzer.diagnose(incident)
        formatted = format_rca_output(res)
        print(formatted)

        top_cause = res.primary_causes[0]
        sec_verdict = res.security_verdict.get("verdict", "BENIGN")
        summary_table.append({
            "scenario": name,
            "service": incident.service_name,
            "top_hypothesis": top_cause.hypothesis_id,
            "confidence": f"{res.overall_confidence:.1%}",
            "security": sec_verdict
        })

    print("\n" + "=" * 90)
    print(" LIVE REAL-TIME EVALUATION MATRIX SUMMARY")
    print("=" * 90)
    print(f"{'SCENARIO':<36} | {'SERVICE':<16} | {'TOP HYPOTHESIS':<22} | {'CONF':<7} | {'SECURITY'}")
    print("-" * 90)
    for row in summary_table:
        print(f"{row['scenario']:<36} | {row['service']:<16} | {row['top_hypothesis']:<22} | {row['confidence']:<7} | {row['security']}")
    print("=" * 90 + "\n")


def main():
    parser = argparse.ArgumentParser(description="UMBRELLA Agent 1 Root Cause Intelligence for OpenTelemetry Demo")
    parser.add_argument("--all", action="store_true", help="Run all live incident scenarios")
    parser.add_argument("--scenario", type=str, help="Run a specific scenario by key name")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of text report")
    args = parser.parse_args()

    analyzer = RootCauseAnalyzer()
    scenarios = AstronomyShopIncidentSimulator.get_all_scenarios()

    if args.scenario:
        if args.scenario not in scenarios:
            print(f"Unknown scenario '{args.scenario}'. Available: {list(scenarios.keys())}")
            sys.exit(1)
        inc = scenarios[args.scenario]
        res = analyzer.diagnose(inc)
        if args.json:
            print(res.model_dump_json(indent=2))
        else:
            print(format_rca_output(res))
    else:
        run_all_scenarios()


if __name__ == "__main__":
    main()
