# OpenTelemetry Astronomy Shop Demo - Project UMBRELLA Integration

This repository is integrated with **Project UMBRELLA's Production-Grade Root Cause Intelligence Agent (Agent 1)**.

## Architecture Overview

Project UMBRELLA's Root Cause Analyzer (Agent 1) connects directly to the OpenTelemetry Astronomy Shop webstore architecture, monitoring telemetry, traces, metrics, and logs across:
- **`frontend` / `frontend-proxy`**: Next.js UI & Envoy proxy (DDoS traffic surge detection, rate limits, latency SLAs)
- **`checkout` (`checkoutservice`)**: Go order orchestration (outbound payment timeouts, downstream cascades)
- **`payment` (`paymentservice`)**: Node.js payment processing (gateway timeouts, credential stuffing / JWT brute force)
- **`cart` (`cartservice`)**: C# .NET state storage (PostgreSQL connection pool saturation)
- **`product-catalog` (`productcatalogservice`)**: Go product lookup (SQL injection detection in search parameters)
- **`accounting` (`accountingservice`)**: Order persistence (SQLite table write lock contention)
- **`otel-collector`**: OpenTelemetry Collector forwarding traces, spans, and metrics to UMBRELLA

## Agent 1 (RCA) Core Capabilities

1. **Multi-Signal Correlation**:
   - **Signal 1 (35%)**: Stack trace AST & call-chain inspection
   - **Signal 2 (30%)**: Telemetry & resource saturation (connection pool util, P99 latency, error counts)
   - **Signal 3 (20%)**: Target service configuration AST state (pool size, overflow limits)
   - **Signal 4 (15%)**: Curated hybrid RAG knowledge grounding & incident runbooks
2. **Competing Hypotheses & Dual Evidence**:
   - Evaluates at least 7 competing hypotheses simultaneously (`HYP-GATEWAY-TIMEOUT`, `HYP-POOL-STARVATION`, `HYP-DB-LOCK`, `HYP-AUTH-CASCADE`, `HYP-SCHEMA-VALIDATION`, `HYP-ATTACK-DDOS`, `HYP-ATTACK-AUTH`, `HYP-ATTACK-SQLI`).
   - Applies explicit supporting evidence bonuses and contradicting evidence penalties.
   - Resolves the "Timeout Trap" (distinguishing external gateway socket timeouts from internal connection pool exhaustion).
3. **Temporal Ordering (T0 -> T4)**:
   - Reconstructs exact timeline: T0 (Trigger) -> T1 (Saturation) -> T2 (Bottleneck) -> T3 (Symptom) -> T4 (Observation).
4. **Security Threat Detection**:
   - Flags traffic surge floods (DDoS), credential stuffing (auth brute force), and SQL injection attempts.
5. **Safe Diagnostic Check Recommendations**:
   - Recommends non-destructive probes before executing remediation.

## Real-Time Scenarios & CLI Usage

Run all real-time incident scenarios through the diagnostic engine:

```bash
cd src
python -m umbrella_rca.cli --all
```

Run a specific scenario (e.g. `checkout_payment_timeout`):

```bash
python -m umbrella_rca.cli --scenario checkout_payment_timeout
```

Run the real-time diagnostic API server:

```bash
python -m umbrella_rca.server
```

Run with Docker Compose:

```bash
docker compose -f compose.yaml -f compose.umbrella.yaml up umbrella-rca-agent
```
