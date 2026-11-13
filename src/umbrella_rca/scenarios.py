"""
Project UMBRELLA - OpenTelemetry Astronomy Shop Demo Integration
Real-Time Incident Scenarios Simulator for Astronomy Shop Services
"""

from typing import Dict, List, Optional
from .schemas import IncidentContext, TelemetrySnapshot, ErrorEvent


class AstronomyShopIncidentSimulator:
    """
    Simulates production incident scenarios mapped directly to the OpenTelemetry
    Astronomy Shop microservices (checkoutservice, paymentservice, cartservice,
    frontend, productcatalogservice).
    """

    @staticmethod
    def checkout_payment_timeout() -> IncidentContext:
        """
        Scenario 1: Checkout payment timeout (Resolves 'Timeout Trap').
        CheckoutService invokes PaymentService charge, but the external 3rd-party
        payment gateway socket times out (HTTP 504 Gateway Timeout).
        Pool utilization is nominal (15%), proving this is NOT pool starvation.
        """
        return IncidentContext(
            incident_id="INC-OTEL-CHECKOUT-001",
            title="CheckoutService payment transaction failed: 3rd-party gateway unresponsive",
            service_name="checkoutservice",
            environment="opentelemetry-demo",
            telemetry=TelemetrySnapshot(
                service_name="paymentservice",
                active_connections=2,
                pool_size=20,
                pool_overflow=5,
                pool_utilization_pct=10.0,
                latency_p99_ms=4500.0,
                error_count_last_5m=12
            ),
            errors=[
                ErrorEvent(
                    event_id="ERR-CHECKOUT-TIMEOUT-01",
                    service_name="paymentservice",
                    error_type="GatewayTimeoutError",
                    error_message="HTTP 504 Gateway Timeout: external payment aggregator unresponsive after 5000ms",
                    stack_trace=(
                        'File "src/checkout/main.go", line 142, in PlaceOrder\n'
                        '  chargeResp, err := paymentClient.Charge(ctx, req)\n'
                        'File "src/payment/charge.js", line 88, in chargeCard\n'
                        '  throw new Error("HTTP 504 Gateway Timeout: aggregator unresponsive");\n'
                    ),
                    target_file="src/payment/charge.js",
                    line_number=88,
                    function_name="chargeCard"
                )
            ]
        )

    @staticmethod
    def cart_db_pool_saturation() -> IncidentContext:
        """
        Scenario 2: Cart service database connection pool starvation.
        Sudden influx of cart operations exhausts PostgreSQL connection pool.
        Pool utilization is 500% (25 active connections against pool size 5).
        """
        return IncidentContext(
            incident_id="INC-OTEL-CART-POOL-002",
            title="CartService PostgreSQL pool starvation under checkout surge",
            service_name="cartservice",
            environment="opentelemetry-demo",
            telemetry=TelemetrySnapshot(
                service_name="cartservice",
                active_connections=25,
                pool_size=5,
                pool_overflow=0,
                pool_utilization_pct=500.0,
                latency_p99_ms=1850.0,
                error_count_last_5m=19
            ),
            errors=[
                ErrorEvent(
                    event_id="ERR-CART-POOL-01",
                    service_name="cartservice",
                    error_type="Npgsql.NpgsqlException",
                    error_message="QueuePool limit of size 5 overflow 0 reached, connection timed out, timeout 2.00s",
                    stack_trace=(
                        'File "src/cart/src/CartService.cs", line 95, in AddItemAsync\n'
                        '  await using var conn = await _dataSource.OpenConnectionAsync();\n'
                        'File "src/cart/src/DatabasePool.cs", line 42, in OpenConnectionAsync\n'
                        '  throw new TimeoutException("QueuePool limit reached, exhausted all 5 slots");\n'
                    ),
                    target_file="src/cart/src/DatabasePool.cs",
                    line_number=42,
                    function_name="OpenConnectionAsync"
                )
            ]
        )

    @staticmethod
    def frontend_ddos_traffic_surge() -> IncidentContext:
        """
        Scenario 3: Security Attack - DDoS Traffic Surge.
        Massive unthrottled concurrent burst on Astronomy Shop Frontend,
        causing SLA latency degradation (P99 > 4000ms) and rate limit alarms.
        """
        return IncidentContext(
            incident_id="INC-OTEL-FRONTEND-DDOS-003",
            title="Astronomy Shop Frontend DDoS surge overwhelming Envoy proxy SLA",
            service_name="frontend",
            environment="opentelemetry-demo",
            telemetry=TelemetrySnapshot(
                service_name="frontend",
                active_connections=45,
                pool_size=10,
                pool_overflow=2,
                pool_utilization_pct=450.0,
                latency_p99_ms=4200.0,
                error_count_last_5m=38
            ),
            errors=[
                ErrorEvent(
                    event_id="ERR-FRONTEND-SURGE-01",
                    service_name="frontend",
                    error_type="EnvoyDownstreamSaturationError",
                    error_message="HTTP 503 Service Unavailable: upstream connection queue flooded by abnormal burst",
                    stack_trace=(
                        'File "src/frontend-proxy/envoy.tmpl.yaml", line 55, in envoy_router\n'
                        '  circuit_breakers: max_connections: 50 exceeded\n'
                        'File "src/frontend/pages/api/cart.ts", line 32, in handler\n'
                        '  throw new Error("EnvoyDownstreamSaturationError: concurrent surge SLA violated");\n'
                    ),
                    target_file="src/frontend/pages/api/cart.ts",
                    line_number=32,
                    function_name="handler"
                )
            ]
        )

    @staticmethod
    def payment_credential_stuffing_attack() -> IncidentContext:
        """
        Scenario 4: Security Attack - Credential Stuffing / Auth Flood.
        Repeated unauthorized access attempts against Payment / Auth service.
        High error count with 401 Unauthorized signatures.
        """
        return IncidentContext(
            incident_id="INC-OTEL-PAYMENT-AUTH-004",
            title="Credential stuffing and JWT brute force attack on paymentservice",
            service_name="paymentservice",
            environment="opentelemetry-demo",
            telemetry=TelemetrySnapshot(
                service_name="paymentservice",
                active_connections=3,
                pool_size=10,
                pool_overflow=0,
                pool_utilization_pct=30.0,
                latency_p99_ms=180.0,
                error_count_last_5m=24
            ),
            errors=[
                ErrorEvent(
                    event_id="ERR-AUTH-BRUTE-01",
                    service_name="paymentservice",
                    error_type="UnauthorizedAuthError",
                    error_message="HTTP 401 Unauthorized: invalid JWT signature, expired bearer token rejected",
                    stack_trace=(
                        'File "src/payment/middleware/auth.js", line 28, in verifyToken\n'
                        '  throw new jwt.ExpiredSignatureError("HTTP 401 Unauthorized: token signature invalid");\n'
                    ),
                    target_file="src/payment/middleware/auth.js",
                    line_number=28,
                    function_name="verifyToken"
                )
            ]
        )

    @staticmethod
    def search_sql_injection_attack() -> IncidentContext:
        """
        Scenario 5: Security Attack - SQL Injection probe in catalog search.
        Malicious query parameters intercepted in product catalog service.
        """
        return IncidentContext(
            incident_id="INC-OTEL-CATALOG-SQLI-005",
            title="SQL Injection attempt in Astronomy Shop product catalog search",
            service_name="productcatalogservice",
            environment="opentelemetry-demo",
            telemetry=TelemetrySnapshot(
                service_name="productcatalogservice",
                active_connections=4,
                pool_size=10,
                pool_overflow=0,
                pool_utilization_pct=40.0,
                latency_p99_ms=220.0,
                error_count_last_5m=3
            ),
            errors=[
                ErrorEvent(
                    event_id="ERR-SQLI-01",
                    service_name="productcatalogservice",
                    error_type="DatabaseSyntaxError",
                    error_message="Syntax error in SQL query near 'UNION SELECT 1,2,3--': unescaped parameter",
                    stack_trace=(
                        'File "src/product-catalog/main.go", line 210, in SearchProducts\n'
                        '  query := "SELECT * FROM products WHERE name LIKE \'%" + searchParam + "%\'"\n'
                        '  // Malicious parameter: telescope\' UNION SELECT 1, password, 3 FROM users--\n'
                    ),
                    target_file="src/product-catalog/main.go",
                    line_number=210,
                    function_name="SearchProducts"
                )
            ]
        )

    @staticmethod
    def sqlite_order_lock_contention() -> IncidentContext:
        """
        Scenario 6: SQLite table write lock contention in transaction log.
        Concurrent transactions cause OperationalError: database is locked.
        """
        return IncidentContext(
            incident_id="INC-OTEL-LOCK-006",
            title="Database lock contention: SQLite write lock timeout during concurrent order recording",
            service_name="accountingservice",
            environment="opentelemetry-demo",
            telemetry=TelemetrySnapshot(
                service_name="accountingservice",
                active_connections=8,
                pool_size=10,
                pool_overflow=0,
                pool_utilization_pct=80.0,
                latency_p99_ms=3100.0,
                error_count_last_5m=7
            ),
            errors=[
                ErrorEvent(
                    event_id="ERR-LOCK-01",
                    service_name="accountingservice",
                    error_type="sqlite3.OperationalError",
                    error_message="OperationalError: database is locked, timeout after 5000ms busy wait",
                    stack_trace=(
                        'File "src/accounting/order_recorder.py", line 74, in record_transaction\n'
                        '  cursor.execute("INSERT INTO orders VALUES (?, ?, ?)", (order_id, amount, ts))\n'
                        'File "sqlite3/dbapi2.py", line 120, in execute\n'
                        '  raise OperationalError("database is locked")\n'
                    ),
                    target_file="src/accounting/order_recorder.py",
                    line_number=74,
                    function_name="record_transaction"
                )
            ]
        )

    @classmethod
    def get_all_scenarios(cls) -> Dict[str, IncidentContext]:
        """Returns all simulated incident scenarios keyed by scenario id."""
        return {
            "checkout_payment_timeout": cls.checkout_payment_timeout(),
            "cart_db_pool_saturation": cls.cart_db_pool_saturation(),
            "frontend_ddos_traffic_surge": cls.frontend_ddos_traffic_surge(),
            "payment_credential_stuffing_attack": cls.payment_credential_stuffing_attack(),
            "search_sql_injection_attack": cls.search_sql_injection_attack(),
            "sqlite_order_lock_contention": cls.sqlite_order_lock_contention()
        }
