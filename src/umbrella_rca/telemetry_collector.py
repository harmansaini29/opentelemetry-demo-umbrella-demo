"""
Project UMBRELLA - OpenTelemetry Astronomy Shop Demo Integration
OpenTelemetry Telemetry Normalizer & OTLP Span Ingestor
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from .schemas import IncidentContext, TelemetrySnapshot, ErrorEvent


class OTelTelemetryNormalizer:
    """
    Transforms OpenTelemetry OTLP spans, Prometheus metrics, and error logs
    into normalized UMBRELLA IncidentContext and TelemetrySnapshot objects.
    """

    @classmethod
    def from_prometheus_metrics(cls, service_name: str, metric_map: Dict[str, float]) -> TelemetrySnapshot:
        """
        Builds a TelemetrySnapshot from Prometheus key-value gauges.
        Standard OTel demo metrics include:
        - `http.server.duration.p99` or `app_latency_p99_ms`
        - `app_db_connections_active` or `db_pool_active`
        - `app_db_pool_size` or `db_pool_size`
        - `app_db_pool_utilization`
        - `http.server.request.error_count`
        """
        active = int(metric_map.get("app_db_connections_active", metric_map.get("db_pool_active", 0)))
        size = int(metric_map.get("app_db_pool_size", metric_map.get("db_pool_size", 10)))
        overflow = int(metric_map.get("app_db_pool_overflow", 0))
        p99 = metric_map.get("http.server.duration.p99", metric_map.get("app_latency_p99_ms", 120.0))
        err_count = int(metric_map.get("http.server.request.error_count", metric_map.get("error_count_5m", 0)))

        util_pct = (active / max(1, size)) * 100.0 if "app_db_pool_utilization" not in metric_map else metric_map["app_db_pool_utilization"]

        return TelemetrySnapshot(
            service_name=service_name,
            timestamp=datetime.now(timezone.utc),
            active_connections=active,
            pool_size=size,
            pool_overflow=overflow,
            pool_utilization_pct=round(util_pct, 2),
            latency_p99_ms=round(p99, 2),
            error_count_last_5m=err_count,
            custom_metrics=metric_map
        )

    @classmethod
    def from_otlp_span(cls, span_data: Dict[str, Any]) -> Optional[ErrorEvent]:
        """
        Extracts an ErrorEvent from an OpenTelemetry span JSON dictionary.
        """
        status = span_data.get("status", {})
        is_error = status.get("code") in [2, "STATUS_CODE_ERROR", "ERROR"]

        events = span_data.get("events", [])
        exception_event = None
        for evt in events:
            if evt.get("name") == "exception":
                exception_event = evt
                break

        if not is_error and not exception_event:
            return None

        attributes = span_data.get("attributes", {})
        service_name = span_data.get("service_name", attributes.get("service.name", "unknown_service"))
        error_type = "UnknownSpanError"
        error_message = status.get("description", "OpenTelemetry span marked with error status")
        stack_trace = ""

        if exception_event:
            evt_attrs = exception_event.get("attributes", {})
            error_type = evt_attrs.get("exception.type", error_type)
            error_message = evt_attrs.get("exception.message", error_message)
            stack_trace = evt_attrs.get("exception.stacktrace", "")

        return ErrorEvent(
            event_id=f"OTEL-SPAN-{span_data.get('span_id', uuid.uuid4().hex[:8])}",
            service_name=service_name,
            timestamp=datetime.now(timezone.utc),
            error_type=error_type,
            error_message=error_message,
            stack_trace=stack_trace,
            target_file=attributes.get("code.filepath"),
            line_number=attributes.get("code.lineno"),
            function_name=attributes.get("code.function", span_data.get("name"))
        )

    @classmethod
    def create_incident(
        cls,
        service_name: str,
        title: str,
        telemetry: Optional[TelemetrySnapshot],
        errors: List[ErrorEvent],
        raw_logs: Optional[str] = None
    ) -> IncidentContext:
        """Constructs a normalized IncidentContext."""
        return IncidentContext(
            incident_id=f"INC-OTEL-{uuid.uuid4().hex[:8].upper()}",
            title=title,
            service_name=service_name,
            telemetry=telemetry,
            errors=errors,
            raw_logs=raw_logs,
            environment="opentelemetry-demo"
        )
