"""Payment execution for Compact Checkout: PayPal Orders v2 adapters.

The decoder gate is the only entrance to this module. `checkout_and_pay`
accepts a DecodeResult and touches a payment adapter only when the packet
status is "approved", the result was verified against the buyer's
device-pinned context (decoder.DeviceContext), and the buyer has
confirmed; every other result is refused before the adapter is called.
A packet that has already been captured is refused as a replay: adapters
keep an idempotency ledger keyed on (packet checksum, amount).

Amounts are integer cents everywhere in this module. The PayPal API takes
decimal strings ("134.24"); conversion happens in exactly one place,
`format_amount`, at the API boundary.

Adapters:
    MockPayPalAdapter    — deterministic, in-memory; no network.
    SandboxPayPalAdapter — real PayPal sandbox (Orders v2), stdlib only.
                           Credentials come from the environment:
                           PAYPAL_SANDBOX_CLIENT_ID,
                           PAYPAL_SANDBOX_CLIENT_SECRET.
"""

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from .packet import is_int

SANDBOX_BASE_URL = "https://api-m.sandbox.paypal.com"
ENV_CLIENT_ID = "PAYPAL_SANDBOX_CLIENT_ID"
ENV_CLIENT_SECRET = "PAYPAL_SANDBOX_CLIENT_SECRET"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PaymentError(Exception):
    """Base class for payment-stage errors."""


class PaymentRefused(PaymentError):
    """The decoder result does not authorize a payment. Raised before any
    adapter call is made."""


class PaymentDeclined(PaymentError):
    """The payment provider declined the capture."""


class CredentialsMissing(PaymentError):
    """Required PayPal sandbox credentials are not in the environment."""


class PayPalAPIError(PaymentError):
    """Transport or API-level failure talking to PayPal."""


# ---------------------------------------------------------------------------
# Amount formatting (the single cents -> decimal-string boundary)
# ---------------------------------------------------------------------------


def format_amount(amount_cents):
    """Format integer cents as a PayPal decimal string: 13424 -> "134.24"."""
    if not is_int(amount_cents) or amount_cents < 0:
        raise ValueError("amount must be a non-negative integer number of cents")
    return "%d.%02d" % (amount_cents // 100, amount_cents % 100)


# ---------------------------------------------------------------------------
# Adapter protocol
# ---------------------------------------------------------------------------


@dataclass
class CaptureResult:
    order_id: str
    transaction_id: str  # the capture id issued by the provider
    status: str  # provider status, e.g. "COMPLETED"
    amount_cents: int
    currency: str


class PaymentAdapter(Protocol):
    """Interface every payment backend implements."""

    def create_order(self, amount_cents: int, currency: str, reference: str) -> str:
        """Create a payment order for an exact amount; return the order id."""
        ...

    def capture_order(self, order_id: str) -> CaptureResult:
        """Capture a created order; return the capture result."""
        ...

    def find_capture(self, reference: str, amount_cents: int) -> str:
        """Idempotency lookup: if this adapter has already captured a
        payment for (reference, amount_cents), return its transaction id;
        otherwise return None."""
        ...


# ---------------------------------------------------------------------------
# Mock adapter
# ---------------------------------------------------------------------------


class MockPayPalAdapter:
    """Deterministic in-memory adapter. IDs are namespaced "MOCK-".

    Every call is appended to `calls` as (method_name, args_dict) so tests
    can assert call counts and arguments. Set `simulate_decline` to make
    captures raise PaymentDeclined.
    """

    def __init__(self, simulate_decline=False):
        self.simulate_decline = simulate_decline
        self.calls = []
        self._order_seq = 0
        self._capture_seq = 0
        self._orders = {}  # order_id -> (amount_cents, currency, reference)
        self._capture_ledger = {}  # (reference, amount_cents) -> transaction_id

    def create_order(self, amount_cents, currency, reference):
        if not is_int(amount_cents) or amount_cents <= 0:
            raise ValueError("order amount must be a positive integer (cents)")
        self._order_seq += 1
        order_id = "MOCK-%017d" % self._order_seq
        self._orders[order_id] = (amount_cents, currency, reference)
        self.calls.append(
            (
                "create_order",
                {
                    "amount_cents": amount_cents,
                    "currency": currency,
                    "reference": reference,
                },
            )
        )
        return order_id

    def capture_order(self, order_id):
        self.calls.append(("capture_order", {"order_id": order_id}))
        if order_id not in self._orders:
            raise PayPalAPIError("unknown order id: %s" % order_id)
        if self.simulate_decline:
            raise PaymentDeclined("capture declined (simulated)")
        amount_cents, currency, reference = self._orders[order_id]
        self._capture_seq += 1
        result = CaptureResult(
            order_id=order_id,
            transaction_id="MOCK-CAP-%013d" % self._capture_seq,
            status="COMPLETED",
            amount_cents=amount_cents,
            currency=currency,
        )
        self._capture_ledger[(reference, amount_cents)] = result.transaction_id
        return result

    def find_capture(self, reference, amount_cents):
        return self._capture_ledger.get((reference, amount_cents))


# ---------------------------------------------------------------------------
# PayPal sandbox adapter (Orders v2, standard library only)
# ---------------------------------------------------------------------------


class SandboxPayPalAdapter:
    """PayPal sandbox client: OAuth2 client-credentials + Orders v2.

    Raises CredentialsMissing at construction if the credential
    environment variables are unset or empty. Credential values are never
    stored in logs, results, or error messages.
    """

    def __init__(self, base_url=SANDBOX_BASE_URL, timeout=30,
                 allow_insecure=False):
        # The client secret travels as HTTP Basic credentials: refuse a
        # non-HTTPS base URL unless the caller explicitly opts in (e.g. a
        # local test double). Default is to refuse.
        if not allow_insecure and urllib.parse.urlparse(base_url).scheme != "https":
            raise ValueError(
                "refusing non-HTTPS PayPal base URL %r: credentials would "
                "be sent in plaintext (pass allow_insecure=True only for "
                "a local test double)" % (base_url,)
            )
        client_id = os.environ.get(ENV_CLIENT_ID)
        client_secret = os.environ.get(ENV_CLIENT_SECRET)
        if not client_id or not client_secret:
            raise CredentialsMissing(
                "PayPal sandbox credentials not set: %s and %s are required"
                % (ENV_CLIENT_ID, ENV_CLIENT_SECRET)
            )
        self._client_id = client_id
        self._client_secret = client_secret
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._token = None
        self._token_expires_at = 0.0
        self._orders = {}  # order_id -> (amount_cents, currency, reference)
        self._capture_ledger = {}  # (reference, amount_cents) -> transaction_id

    # -- HTTP plumbing ------------------------------------------------------

    def _request(self, method, path, body=None, headers=None):
        url = self._base_url + path
        data = None
        hdrs = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise PayPalAPIError(
                "PayPal API error: HTTP %d on %s %s" % (exc.code, method, path)
            ) from exc
        except urllib.error.URLError as exc:
            raise PayPalAPIError(
                "PayPal request failed (%s %s): %s" % (method, path, exc.reason)
            ) from exc
        try:
            return json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            raise PayPalAPIError("PayPal returned a non-JSON response") from exc

    def _access_token(self):
        # Reuse the cached token until it is within 60 seconds of expiry.
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token
        basic = base64.b64encode(
            ("%s:%s" % (self._client_id, self._client_secret)).encode("utf-8")
        ).decode("ascii")
        req = urllib.request.Request(
            self._base_url + "/v1/oauth2/token",
            data=b"grant_type=client_credentials",
            headers={
                "Authorization": "Basic " + basic,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise PayPalAPIError(
                "PayPal token request failed: HTTP %d" % exc.code
            ) from exc
        except urllib.error.URLError as exc:
            raise PayPalAPIError(
                "PayPal token request failed: %s" % exc.reason
            ) from exc
        token = payload.get("access_token")
        if not token:
            raise PayPalAPIError("PayPal token response carried no access_token")
        self._token = token
        self._token_expires_at = time.time() + int(payload.get("expires_in", 3600))
        return token

    def _auth_headers(self):
        return {"Authorization": "Bearer " + self._access_token()}

    # -- PaymentAdapter interface -------------------------------------------

    def create_order(self, amount_cents, currency, reference):
        if not is_int(amount_cents) or amount_cents <= 0:
            raise ValueError("order amount must be a positive integer (cents)")
        body = {
            "intent": "CAPTURE",
            "purchase_units": [
                {
                    "reference_id": reference,
                    "amount": {
                        "currency_code": currency,
                        "value": format_amount(amount_cents),
                    },
                }
            ],
        }
        payload = self._request(
            "POST", "/v2/checkout/orders", body=body, headers=self._auth_headers()
        )
        order_id = payload.get("id")
        if not order_id:
            raise PayPalAPIError("PayPal order response carried no id")
        self._orders[order_id] = (amount_cents, currency, reference)
        return order_id

    def capture_order(self, order_id):
        payload = self._request(
            "POST",
            "/v2/checkout/orders/%s/capture" % order_id,
            body={},
            headers=self._auth_headers(),
        )
        status = payload.get("status")
        try:
            capture = payload["purchase_units"][0]["payments"]["captures"][0]
        except (KeyError, IndexError, TypeError) as exc:
            raise PayPalAPIError(
                "PayPal capture response is missing capture detail"
            ) from exc
        if capture.get("status") != "COMPLETED":
            raise PaymentDeclined(
                "capture status is %s" % capture.get("status")
            )
        value = capture["amount"]["value"]
        dollars, _, cents = value.partition(".")
        amount_cents = int(dollars) * 100 + int((cents + "00")[:2])
        result = CaptureResult(
            order_id=order_id,
            transaction_id=capture["id"],
            status=status or capture["status"],
            amount_cents=amount_cents,
            currency=capture["amount"]["currency_code"],
        )
        known = self._orders.get(order_id)
        if known is not None:
            self._capture_ledger[(known[2], amount_cents)] = result.transaction_id
        return result

    def find_capture(self, reference, amount_cents):
        return self._capture_ledger.get((reference, amount_cents))


# ---------------------------------------------------------------------------
# The seam: gated decode result -> payment
# ---------------------------------------------------------------------------


@dataclass
class PaymentReceipt:
    """Confirmation record. On success it pairs the provider transaction
    with the packet checksum: the amount charged is the amount the packet
    stated and the buyer approved."""

    status: str  # "captured" | "failed"
    order_id: str = None
    transaction_id: str = None
    amount_cents: int = None
    currency: str = None
    packet_checksum: str = None
    reason: str = None


def checkout_and_pay(decoded_result, adapter, buyer_confirmed=False):
    """Execute payment for a gated decode result via `adapter`.

    Refuses (PaymentRefused, adapter untouched) unless the result status
    is "approved", the result was verified against the buyer's
    device-pinned context, and `buyer_confirmed` is true. A provider
    decline is returned as a receipt with status "failed", never as a
    success.

    Replay: a second presentation of the same packet is refused via the
    adapter's idempotency ledger, keyed on (packet checksum, amount), so
    one packet captures at most once per adapter. NOTE: keying on the
    checksum means a byte-identical repeat purchase is also refused by
    this prototype; production adds a packet nonce and expiry (a wire
    header change, deliberately NOT made in format v0) so legitimate
    repeat purchases stay possible while true replays stay rejected. At
    the provider, the order reference also serves as the PayPal
    idempotency anchor for the capture itself.
    """
    if decoded_result.status == "blocked":
        raise PaymentRefused(
            "packet is blocked: %s" % "; ".join(decoded_result.reasons)
        )
    if decoded_result.status == "needs_confirmation":
        raise PaymentRefused(
            "packet is above the mandate ask-threshold; explicit buyer "
            "confirmation through the confirmation flow is required first"
        )
    if decoded_result.status != "approved":
        raise PaymentRefused(
            "unrecognized decode status: %r" % (decoded_result.status,)
        )
    if not buyer_confirmed:
        raise PaymentRefused("buyer has not confirmed the approval")
    if not getattr(decoded_result, "device_context_verified", False):
        raise PaymentRefused(
            "result was not verified against a device-pinned mandate and "
            "currency (format-validation mode); payment requires the "
            "pinned device context"
        )

    amount_cents = decoded_result.computed_total_cents
    currency = decoded_result.currency
    reference = decoded_result.packet_checksum or "compact-checkout"

    if not is_int(amount_cents) or amount_cents <= 0:
        raise PaymentError(
            "approved packet total must be a positive integer number of "
            "cents to pay: %r" % (amount_cents,)
        )

    existing = adapter.find_capture(reference, amount_cents)
    if existing is not None:
        raise PaymentRefused(
            "packet already captured (transaction %s); replay refused"
            % existing
        )

    order_id = adapter.create_order(amount_cents, currency, reference)
    try:
        capture = adapter.capture_order(order_id)
    except PaymentDeclined as exc:
        return PaymentReceipt(
            status="failed",
            order_id=order_id,
            amount_cents=amount_cents,
            currency=currency,
            packet_checksum=decoded_result.packet_checksum,
            reason=str(exc),
        )
    if capture.amount_cents != amount_cents:
        return PaymentReceipt(
            status="failed",
            order_id=order_id,
            transaction_id=capture.transaction_id,
            amount_cents=amount_cents,
            currency=currency,
            packet_checksum=decoded_result.packet_checksum,
            reason="captured amount does not match the approved packet total",
        )
    return PaymentReceipt(
        status="captured",
        order_id=order_id,
        transaction_id=capture.transaction_id,
        amount_cents=capture.amount_cents,
        currency=capture.currency,
        packet_checksum=decoded_result.packet_checksum,
    )
