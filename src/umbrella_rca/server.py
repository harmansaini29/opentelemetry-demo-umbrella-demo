"""
Project UMBRELLA - OpenTelemetry Astronomy Shop Demo Integration
FastAPI Live Diagnostic Server for Agent 1 (RCA)
"""

import os
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel

from .analyzer import RootCauseAnalyzer
from .scenarios import AstronomyShopIncidentSimulator
from .schemas import IncidentContext, RCAResult
from .telemetry_collector import OTelTelemetryNormalizer

app = FastAPI(
    title="Project UMBRELLA - Root Cause Intelligence Agent (Agent 1)",
    description="Autonomous root cause diagnostics, competing hypotheses ranking, and security threat analysis for OpenTelemetry Astronomy Shop",
    version="1.0.0"
)

analyzer = RootCauseAnalyzer()


@app.get("/health")
def health_check():
    return {
        "status": "online",
        "agent": "Agent 1: Root Cause & Diagnostic Intelligence",
        "system": "OpenTelemetry Astronomy Shop Webstore",
        "monitored_services": [
            "frontend",
            "checkoutservice",
            "paymentservice",
            "cartservice",
            "currencyservice",
            "productcatalogservice",
            "recommendationservice",
            "shippingservice",
            "accountingservice"
        ]
    }


@app.get("/scenarios")
def list_scenarios():
    scenarios = AstronomyShopIncidentSimulator.get_all_scenarios()
    return {
        "count": len(scenarios),
        "scenarios": [
            {
                "id": key,
                "incident_id": inc.incident_id,
                "title": inc.title,
                "service": inc.service_name,
                "error_type": inc.errors[0].error_type if inc.errors else "None"
            }
            for key, inc in scenarios.items()
        ]
    }


@app.post("/diagnose", response_model=RCAResult)
def diagnose_incident(incident: IncidentContext):
    """Diagnoses an incoming incident context using Agent 1 multi-signal correlation."""
    try:
        result = analyzer.diagnose(incident)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scenarios/{scenario_id}/execute", response_model=RCAResult)
def execute_scenario(scenario_id: str):
    """Executes a simulated real-time incident scenario and runs live Agent 1 evaluation."""
    scenarios = AstronomyShopIncidentSimulator.get_all_scenarios()
    if scenario_id not in scenarios:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found. Available: {list(scenarios.keys())}")
    
    incident = scenarios[scenario_id]
    result = analyzer.diagnose(incident)
    return result


@app.post("/otlp/v1/traces")
def ingest_otlp_trace_span(span_payload: Dict[str, Any] = Body(...)):
    """Ingests a raw OTLP trace span, generates an ErrorEvent, and triggers real-time RCA if error."""
    error_event = OTelTelemetryNormalizer.from_otlp_span(span_payload)
    if not error_event:
        return {"status": "ignored", "reason": "span does not indicate error or exception"}

    incident = OTelTelemetryNormalizer.create_incident(
        service_name=error_event.service_name,
        title=f"OTLP Trace Anomaly in {error_event.service_name}: {error_event.error_type}",
        telemetry=None,
        errors=[error_event]
    )

    result = analyzer.diagnose(incident)
    return {
        "status": "diagnosed",
        "incident_id": incident.incident_id,
        "top_hypothesis": result.primary_causes[0].hypothesis_id,
        "confidence": result.overall_confidence,
        "security_verdict": result.security_verdict
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("UMBRELLA_RCA_PORT", "8085"))
    uvicorn.run("umbrella_rca.server:app", host="0.0.0.0", port=port, reload=False)
