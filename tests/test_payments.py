"""Payment-stage tests: gated seam, mock adapter, sandbox adapter shape.

No live network calls: the sandbox tests stub urllib.request.urlopen.
"""

import json
import os
import unittest
import urllib.request
from unittest import mock

from compact_checkout import (
    CheckoutIntent,
    CredentialsMissing,
    DeviceContext,
    LineItem,
    Mandate,
    MockPayPalAdapter,
    PaymentError,
    PaymentRefused,
    SandboxPayPalAdapter,
    checkout_and_pay,
    compress,
    decode,
    format_amount,
)
from compact_checkout.payments import ENV_CLIENT_ID, ENV_CLIENT_SECRET
from scenarios import (
    GROCERY_DEVICE,
    scenario_1_grocery,
    scenario_2_over_cap,
    scenario_4_tampered,
)


def needs_confirmation_result():
    """Scenario 1 items under a low ask-threshold: valid, under cap,
    above ask — the decoder must return needs_confirmation."""
    _wire, packet, _r = scenario_1_grocery()
    intent = CheckoutIntent(
        merchant="FRSH",
        mandate=Mandate(cap_cents=20000, categories=["GRO", "HH"],
                        ask_threshold_cents=10000),
        items=[LineItem("MLK1", 2, 349), LineItem("DETL", 1, 1579),
               LineItem("COFB", 1, 1249), LineItem("RICE5", 1, 899),
               LineItem("CHKNB", 3, 749), LineItem("EGG12", 1, 429),
               LineItem("BRDSD", 2, 550), LineItem("APLG", 6, 109),
               LineItem("PTWL", 2, 325), LineItem("CHDR", 2, 475),
               LineItem("OJ64", 2, 399), LineItem("PSTA", 4, 129),
               LineItem("TSAU", 4, 189), LineItem("GYOG", 4, 110),
               LineItem("BTTR", 1, 459)],
    )
    wire, _packet = compress(intent)
    result = decode(wire)
    assert result.status == "needs_confirmation", result
    return result


class TestFormatAmount(unittest.TestCase):
    def test_boundary_format(self):
        self.assertEqual(format_amount(13424), "134.24")
        self.assertEqual(format_amount(20000), "200.00")
        self.assertEqual(format_amount(5), "0.05")
        self.assertEqual(format_amount(0), "0.00")
        self.assertEqual(format_amount(1000000), "10000.00")

    def test_rejects_non_integer_and_negative(self):
        for bad in (134.24, "13424", True, -1):
            with self.assertRaises(ValueError):
                format_amount(bad)


class TestMockAdapterSuccess(unittest.TestCase):
    def test_approved_and_confirmed_pays(self):
        _wire, packet, result = scenario_1_grocery()
        adapter = MockPayPalAdapter()
        receipt = checkout_and_pay(result, adapter, buyer_confirmed=True)
        self.assertEqual(receipt.status, "captured")
        self.assertEqual(receipt.amount_cents, 13424)
        self.assertEqual(receipt.currency, "USD")
        self.assertTrue(receipt.order_id.startswith("MOCK-"))
        self.assertTrue(receipt.transaction_id.startswith("MOCK-"))
        # The receipt pairs the transaction with the packet checksum.
        self.assertEqual(receipt.packet_checksum, packet["ck"])
        self.assertEqual(
            [name for name, _args in adapter.calls],
            ["create_order", "capture_order"],
        )
        create_args = adapter.calls[0][1]
        self.assertEqual(create_args["amount_cents"], 13424)
        self.assertEqual(create_args["reference"], packet["ck"])


class TestRefusalsTouchNothing(unittest.TestCase):
    def assert_refused(self, result, confirmed):
        adapter = MockPayPalAdapter()
        with self.assertRaises(PaymentRefused):
            checkout_and_pay(result, adapter, buyer_confirmed=confirmed)
        self.assertEqual(adapter.calls, [])

    def test_blocked_over_cap(self):
        _w, _p, result = scenario_2_over_cap()
        self.assertEqual(result.status, "blocked")
        self.assert_refused(result, confirmed=True)

    def test_blocked_tampered(self):
        _w, _p, result = scenario_4_tampered()
        self.assertEqual(result.status, "blocked")
        self.assert_refused(result, confirmed=True)

    def test_needs_confirmation(self):
        self.assert_refused(needs_confirmation_result(), confirmed=True)

    def test_approved_but_unconfirmed(self):
        _w, _p, result = scenario_1_grocery()
        self.assertEqual(result.status, "approved")
        self.assert_refused(result, confirmed=False)


class TestDeviceContextRequiredAtSeam(unittest.TestCase):
    def test_validation_mode_result_refused(self):
        # Same wire as scenario 1, decoded WITHOUT a device context:
        # approved in format-validation mode, but the seam must refuse
        # it and never touch the adapter.
        wire, _packet, _r = scenario_1_grocery()
        result = decode(wire)
        self.assertEqual(result.status, "approved")
        self.assertFalse(result.device_context_verified)
        adapter = MockPayPalAdapter()
        with self.assertRaises(PaymentRefused):
            checkout_and_pay(result, adapter, buyer_confirmed=True)
        self.assertEqual(adapter.calls, [])


class TestReplayRefused(unittest.TestCase):
    def test_same_packet_captures_once(self):
        wire, _packet, result = scenario_1_grocery()
        adapter = MockPayPalAdapter()
        receipt = checkout_and_pay(result, adapter, buyer_confirmed=True)
        self.assertEqual(receipt.status, "captured")
        again = decode(wire, device_context=GROCERY_DEVICE)
        self.assertEqual(again.status, "approved")
        with self.assertRaises(PaymentRefused):
            checkout_and_pay(again, adapter, buyer_confirmed=True)
        captures = [c for c in adapter.calls if c[0] == "capture_order"]
        self.assertEqual(len(captures), 1)


class TestZeroTotal(unittest.TestCase):
    def test_zero_total_raises_payment_error_not_value_error(self):
        mandate = Mandate(cap_cents=20000, categories=["GRO"],
                          ask_threshold_cents=15000)
        wire, _packet = compress(CheckoutIntent(
            merchant="FRSH", mandate=mandate,
            items=[LineItem("MLK1", 1, 0)]))
        result = decode(
            wire, device_context=DeviceContext(mandate=mandate,
                                               currency="USD"))
        self.assertEqual(result.status, "approved")
        adapter = MockPayPalAdapter()
        with self.assertRaises(PaymentError) as caught:
            checkout_and_pay(result, adapter, buyer_confirmed=True)
        self.assertNotIsInstance(caught.exception, ValueError)
        self.assertEqual(adapter.calls, [])


class TestDecline(unittest.TestCase):
    def test_decline_is_a_failed_payment_not_an_approval(self):
        _w, _p, result = scenario_1_grocery()
        adapter = MockPayPalAdapter(simulate_decline=True)
        receipt = checkout_and_pay(result, adapter, buyer_confirmed=True)
        self.assertEqual(receipt.status, "failed")
        self.assertIsNone(receipt.transaction_id)
        self.assertIn("declined", receipt.reason)


class _FakeResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestSandboxAdapter(unittest.TestCase):
    def test_missing_credentials_raise_typed_error(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(CredentialsMissing):
                SandboxPayPalAdapter()

    def test_non_https_base_url_refused_by_default(self):
        env = {ENV_CLIENT_ID: "test-id", ENV_CLIENT_SECRET: "test-secret"}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError):
                SandboxPayPalAdapter(base_url="http://127.0.0.1:9")
            # Explicit opt-in for a local test double still constructs.
            adapter = SandboxPayPalAdapter(
                base_url="http://127.0.0.1:9", allow_insecure=True)
            self.assertIsNotNone(adapter)
            # And the HTTPS default constructs without the flag.
            self.assertIsNotNone(SandboxPayPalAdapter())

    def test_request_shapes_and_token_caching(self):
        seen = []

        def fake_urlopen(req, timeout=None):
            seen.append(req)
            url = req.full_url
            if url.endswith("/v1/oauth2/token"):
                auth = req.get_header("Authorization")
                assert auth and auth.startswith("Basic "), auth
                return _FakeResponse(
                    {"access_token": "TEST-TOKEN", "expires_in": 3600}
                )
            if url.endswith("/v2/checkout/orders"):
                assert req.get_header("Authorization") == "Bearer TEST-TOKEN"
                body = json.loads(req.data.decode("utf-8"))
                assert body["intent"] == "CAPTURE"
                unit = body["purchase_units"][0]
                expected_value = {"ref-1": "134.24", "ref-2": "5.00"}[
                    unit["reference_id"]
                ]
                assert unit["amount"] == {
                    "currency_code": "USD",
                    "value": expected_value,
                }
                return _FakeResponse({"id": "SANDBOX-ORDER-1", "status": "CREATED"})
            if url.endswith("/v2/checkout/orders/SANDBOX-ORDER-1/capture"):
                return _FakeResponse(
                    {
                        "id": "SANDBOX-ORDER-1",
                        "status": "COMPLETED",
                        "purchase_units": [
                            {
                                "payments": {
                                    "captures": [
                                        {
                                            "id": "SANDBOX-CAP-1",
                                            "status": "COMPLETED",
                                            "amount": {
                                                "currency_code": "USD",
                                                "value": "134.24",
                                            },
                                        }
                                    ]
                                }
                            }
                        ],
                    }
                )
            raise AssertionError("unexpected URL: %s" % url)

        env = {ENV_CLIENT_ID: "test-id", ENV_CLIENT_SECRET: "test-secret"}
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch.object(urllib.request, "urlopen", fake_urlopen):
                adapter = SandboxPayPalAdapter()
                order_id = adapter.create_order(13424, "USD", "ref-1")
                self.assertEqual(order_id, "SANDBOX-ORDER-1")
                adapter.create_order(500, "USD", "ref-2")
                capture = adapter.capture_order(order_id)
        self.assertEqual(capture.transaction_id, "SANDBOX-CAP-1")
        self.assertEqual(capture.amount_cents, 13424)
        self.assertEqual(capture.currency, "USD")
        token_calls = [
            r for r in seen if r.full_url.endswith("/v1/oauth2/token")
        ]
        self.assertEqual(len(token_calls), 1)  # token cached across calls


if __name__ == "__main__":
    unittest.main()
