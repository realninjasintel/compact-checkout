"""Wire packet model for Compact Checkout.

A packet is a JSON object with a header carried exactly once and line items
as positional arrays. Field keys are short by design; the schema below is
the complete, closed vocabulary of the format. Any key not listed here is
invalid.

Wire layout (v0):

    {
      "v":   1,                 protocol version (int)
      "cb":  1,                 codebook version (int)
      "m":   "FRSH",            merchant code (str, codebook)
      "cur": "USD",             currency code (str)
      "md":  {"cap": 20000,     mandate: spending cap, integer cents
              "cats": ["GRO"],  mandate: allowed category codes
              "ask": 15000},    mandate: ask-threshold, integer cents
      "it":  [["MLK1", 2, 349], ...],   line items:
                                        [item_code, qty, unit_price_cents]
      "lit": "...",             OPTIONAL literal lane: seller free text,
                                length-capped, inert (see decoder)
      "tot": 13424,             stated total, integer cents; present ONLY
                                so the decoder can cross-check it against
                                the sum it computes itself from "it"
      "ck":  "9f3ac21b"         checksum over the canonical packet
    }

Money rule: every amount is an integer number of cents. Floats are invalid
anywhere in a packet and are rejected at validation.

Checksum: FNV-1a 32-bit over the canonical serialization of the packet
without the "ck" field, rendered as 8 lowercase hex digits.

    DEMO-GRADE ONLY: FNV-1a detects accidental corruption and naive
    tampering in this prototype. It is not a cryptographic authenticator.
    The production integration point is the `compute_checksum` function
    below: replace the FNV-1a body with an HMAC (or a digital signature)
    over the same canonical bytes, keyed by the sending agent and verified
    on the device / payment-provider side. No other module needs to change.
"""

import json

PROTOCOL_VERSION = 1

#: Complete set of permitted top-level packet keys (closed vocabulary).
PACKET_KEYS = frozenset({"v", "cb", "m", "cur", "md", "it", "lit", "tot", "ck"})

#: Complete set of permitted mandate-header keys.
MANDATE_KEYS = frozenset({"cap", "cats", "ask"})

#: Keys that must be present in every packet ("lit" is the only optional one).
REQUIRED_KEYS = frozenset({"v", "cb", "m", "cur", "md", "it", "tot", "ck"})

#: Maximum length of the literal lane, in characters.
LITERAL_MAX_CHARS = 200


def canonical_bytes(packet):
    """Serialize a packet deterministically for checksum purposes.

    The checksum field itself is excluded. Keys are sorted and separators
    are compact so the same logical packet always yields the same bytes.
    """
    body = {k: v for k, v in packet.items() if k != "ck"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _fnv1a_32(data):
    """FNV-1a 32-bit hash of `data` (bytes) as an int."""
    h = 0x811C9DC5
    for byte in data:
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def compute_checksum(packet):
    """Return the packet checksum as 8 lowercase hex digits.

    DEMO-GRADE (FNV-1a). Production: HMAC/signature over canonical_bytes()
    — see module docstring.
    """
    return format(_fnv1a_32(canonical_bytes(packet)), "08x")


def serialize(packet):
    """Serialize a complete packet to its minified wire form (str)."""
    return json.dumps(packet, sort_keys=True, separators=(",", ":"))


def parse(wire):
    """Parse wire text into a packet dict.

    Raises ValueError on malformed JSON or a non-object top level. Schema
    validation is the decoder's job, not the parser's.
    """
    try:
        obj = json.loads(wire)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("packet is not valid JSON: %s" % exc) from exc
    if not isinstance(obj, dict):
        raise ValueError("packet top level must be a JSON object")
    return obj


def is_int(value):
    """True for genuine integers. Booleans and floats are not integers here."""
    return isinstance(value, int) and not isinstance(value, bool)
