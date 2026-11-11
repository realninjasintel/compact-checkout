"""Compact Checkout: compressed, checksummed checkout packets with a
deterministic on-device decoder and an arithmetic spending-mandate gate.

Public API:
    CheckoutIntent, LineItem, Mandate  — encoder inputs (compressor)
    compress(intent)                   — intent -> (wire_text, packet)
    DeviceContext                      — buyer device-pinned mandate +
                                         currency (decoder)
    decode(wire_or_packet, device_context=None)
                                       — packet -> DecodeResult (decoder)
    DecodeResult                       — gated decode outcome
    checkout_and_pay(result, adapter)  — gated payment execution (payments)
    codebook                           — the shared codebook (v0)
"""

from . import codebook
from .compressor import CheckoutIntent, LineItem, Mandate, compress, wire_size
from .decoder import DecodeResult, DeviceContext, decode
from .payments import (
    CredentialsMissing,
    MockPayPalAdapter,
    PaymentDeclined,
    PaymentError,
    PaymentReceipt,
    PaymentRefused,
    PayPalAPIError,
    SandboxPayPalAdapter,
    checkout_and_pay,
    format_amount,
)

__all__ = [
    "codebook",
    "CheckoutIntent",
    "LineItem",
    "Mandate",
    "compress",
    "wire_size",
    "decode",
    "DecodeResult",
    "DeviceContext",
    "checkout_and_pay",
    "PaymentReceipt",
    "MockPayPalAdapter",
    "SandboxPayPalAdapter",
    "format_amount",
    "PaymentError",
    "PaymentRefused",
    "PaymentDeclined",
    "CredentialsMissing",
    "PayPalAPIError",
]

__version__ = "0.1.0"
