"""
Comprehensive Test Suite for Project UMBRELLA Root Cause Intelligence Agent (Agent 1)
Integrated with OpenTelemetry Astronomy Shop Webstore
"""

import os
import sys
import unittest

# Ensure src is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from umbrella_rca.analyzer import RootCauseAnalyzer
from umbrella_rca.scenarios import AstronomyShopIncidentSimulator
from umbrella_rca.telemetry_collector import OTelTelemetryNormalizer
from umbrella_rca.schemas import ImpactLevel, ActionRiskTier


class TestUmbrellaRCAAgent(unittest.TestCase):

    def setUp(self):
        self.analyzer = RootCauseAnalyzer()

    def test_scenario1_checkout_payment_timeout_resolves_timeout_trap(self):
        """
        Verify that a 504 gateway timeout with low pool utilization is diagnosed
        as HYP-GATEWAY-TIMEOUT and NOT misdiagnosed as pool starvation.
        """
        incident = AstronomyShopIncidentSimulator.checkout_payment_timeout()
        res = self.analyzer.diagnose(incident)

        self.assertGreater(len(res.primary_causes), 0)
        top_cause = res.primary_causes[0]

        # Top cause must be Gateway Timeout
        self.assertEqual(top_cause.hypothesis_rank, 1)
        self.assertEqual(top_cause.hypothesis_id, "HYP-GATEWAY-TIMEOUT")
        self.assertIn("Gateway Timeout", top_cause.cause)
        self.assertGreaterEqual(top_cause.confidence, 0.65)

        # Pool starvation must be heavily penalized
        pool_hyp = next(h for h in res.competing_hypotheses if h.hypothesis_id == "HYP-POOL-STARVATION")
        self.assertGreater(len(pool_hyp.contradicting_evidence), 0)
        self.assertTrue(any("refutes pool exhaustion" in c.lower() for c in pool_hyp.contradicting_evidence))
        self.assertLess(pool_hyp.confidence, top_cause.confidence)

        # Safe diagnostic check is provided
        self.assertIsNotNone(top_cause.next_safe_diagnostic_check)
        self.assertIn("ping", top_cause.next_safe_diagnostic_check.lower())

    def test_scenario2_cart_db_pool_saturation(self):
        """
        Verify that 500% pool utilization with QueuePool errors is diagnosed
        as HYP-POOL-STARVATION with high confidence.
        """
        incident = AstronomyShopIncidentSimulator.cart_db_pool_saturation()
        res = self.analyzer.diagnose(incident)

        top_cause = res.primary_causes[0]
        self.assertEqual(top_cause.hypothesis_rank, 1)
        self.assertEqual(top_cause.hypothesis_id, "HYP-POOL-STARVATION")
        self.assertIn("connection pool starvation", top_cause.cause.lower())
        self.assertGreaterEqual(top_cause.confidence, 0.85)

        # Supporting evidence checks
        self.assertTrue(any("queuepool" in s.lower() for s in top_cause.supporting_evidence))
        self.assertTrue(any("saturation" in s.lower() for s in top_cause.supporting_evidence))
        self.assertIn("DB_POOL_SIZE", top_cause.remediation_suggestion)

    def test_scenario3_frontend_ddos_traffic_surge(self):
        """
        Verify that abnormal traffic burst and downstream queue flooding is classified
        as a security DDoS attack with HIGH threat level.
        """
        incident = AstronomyShopIncidentSimulator.frontend_ddos_traffic_surge()
        res = self.analyzer.diagnose(incident)

        top_cause = res.primary_causes[0]
        self.assertEqual(top_cause.hypothesis_id, "HYP-ATTACK-DDOS")
        self.assertEqual(top_cause.attack_classification, "TRAFFIC_SURGE_FLOOD")

        # Security verdict checks
        sec = res.security_verdict
        self.assertEqual(sec.get("verdict"), "SECURITY_ATTACK_DETECTED")
        self.assertEqual(sec.get("threat_level"), "HIGH")
        self.assertIn("TRAFFIC_SURGE_FLOOD", sec.get("attack_types", []))
        self.assertIn("rate limiting", sec.get("recommended_action", "").lower())

    def test_scenario4_payment_credential_stuffing(self):
        """
        Verify that multiple 401 Unauthorized rejections trigger
        HYP-ATTACK-AUTH credential stuffing classification.
        """
        incident = AstronomyShopIncidentSimulator.payment_credential_stuffing_attack()
        res = self.analyzer.diagnose(incident)

        top_cause = res.primary_causes[0]
        self.assertEqual(top_cause.hypothesis_id, "HYP-ATTACK-AUTH")
        self.assertEqual(top_cause.attack_classification, "CREDENTIAL_BRUTE_FORCE")

        sec = res.security_verdict
        self.assertEqual(sec.get("verdict"), "SECURITY_ATTACK_DETECTED")
        self.assertIn("CREDENTIAL_BRUTE_FORCE", sec.get("attack_types", []))

    def test_scenario5_search_sql_injection(self):
        """
        Verify that SQL injection patterns in product catalog queries trigger
        HYP-ATTACK-SQLI and penalize benign lock/pool hypotheses.
        """
        incident = AstronomyShopIncidentSimulator.search_sql_injection_attack()
        res = self.analyzer.diagnose(incident)

        top_cause = res.primary_causes[0]
        self.assertEqual(top_cause.hypothesis_id, "HYP-ATTACK-SQLI")
        self.assertEqual(top_cause.attack_classification, "SQL_INJECTION")
        self.assertGreaterEqual(top_cause.confidence, 0.75)

        # Benign lock contention should have penalty from SQL injection
        lock_hyp = next(h for h in res.competing_hypotheses if h.hypothesis_id == "HYP-DB-LOCK")
        self.assertTrue(any("sql injection" in c.lower() for c in lock_hyp.contradicting_evidence))

    def test_scenario6_sqlite_order_lock_contention(self):
        """
        Verify SQLite write lock timeout is diagnosed as HYP-DB-LOCK with WAL/busy_timeout fix.
        """
        incident = AstronomyShopIncidentSimulator.sqlite_order_lock_contention()
        res = self.analyzer.diagnose(incident)

        top_cause = res.primary_causes[0]
        self.assertEqual(top_cause.hypothesis_id, "HYP-DB-LOCK")
        self.assertIn("lock contention", top_cause.cause.lower())
        self.assertIn("PRAGMA busy_timeout", top_cause.remediation_suggestion)

    def test_temporal_ordering_timeline(self):
        """
        Verify that every evaluation produces a complete chronological timeline T0 -> T4.
        """
        incident = AstronomyShopIncidentSimulator.checkout_payment_timeout()
        res = self.analyzer.diagnose(incident)

        t_seq = res.temporal_ordering
        self.assertIn("t0_trigger", t_seq)
        self.assertIn("t1_saturation", t_seq)
        self.assertIn("t2_bottleneck", t_seq)
        self.assertIn("t3_symptom", t_seq)
        self.assertIn("t4_observation", t_seq)
        self.assertIn("payment_gateway_client", t_seq["t2_bottleneck"].lower())

    def test_competing_hypotheses_ranking_and_evidence(self):
        """
        Verify that competing hypotheses are sorted strictly by confidence descending
        and contain dual-evidence (supporting and contradicting) entries.
        """
        for inc_id, incident in AstronomyShopIncidentSimulator.get_all_scenarios().items():
            res = self.analyzer.diagnose(incident)
            self.assertGreaterEqual(len(res.competing_hypotheses), 5)

            # Check descending confidence
            confidences = [h.confidence for h in res.competing_hypotheses]
            self.assertEqual(confidences, sorted(confidences, reverse=True))

            # Check rank ordering
            ranks = [h.hypothesis_rank for h in res.competing_hypotheses]
            self.assertEqual(ranks, list(range(1, len(res.competing_hypotheses) + 1)))

    def test_otlp_telemetry_normalizer(self):
        """
        Verify Prometheus metric parsing and OTLP error span transformation.
        """
        # Prometheus conversion
        metrics = {
            "app_db_connections_active": 18,
            "app_db_pool_size": 20,
            "http.server.duration.p99": 1420.5,
            "http.server.request.error_count": 6
        }
        snap = OTelTelemetryNormalizer.from_prometheus_metrics("currencyservice", metrics)
        self.assertEqual(snap.service_name, "currencyservice")
        self.assertEqual(snap.active_connections, 18)
        self.assertEqual(snap.pool_size, 20)
        self.assertEqual(snap.pool_utilization_pct, 90.0)
        self.assertEqual(snap.latency_p99_ms, 1420.5)

        # OTLP span conversion
        span_data = {
            "name": "ChargePayment",
            "service_name": "paymentservice",
            "status": {"code": 2, "description": "Payment gateway rejected request"},
            "attributes": {"code.filepath": "src/payment/charge.js", "code.lineno": 112},
            "events": [
                {
                    "name": "exception",
                    "attributes": {
                        "exception.type": "PaymentGatewayTimeout",
                        "exception.message": "HTTP 504 Gateway Timeout: connection aborted",
                        "exception.stacktrace": 'File "src/payment/charge.js", line 112, in ChargePayment'
                    }
                }
            ]
        }
        err = OTelTelemetryNormalizer.from_otlp_span(span_data)
        self.assertIsNotNone(err)
        self.assertEqual(err.service_name, "paymentservice")
        self.assertEqual(err.error_type, "PaymentGatewayTimeout")
        self.assertEqual(err.target_file, "src/payment/charge.js")
        self.assertEqual(err.line_number, 112)


if __name__ == "__main__":
    unittest.main()
