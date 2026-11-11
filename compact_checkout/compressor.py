"""Encoder: structured checkout intent -> minified wire packet.

The compressor resolves human-readable item names to codebook codes, keeps
every amount as integer cents, computes the stated total by integer
summation of the line items, attaches the mandate header once, and seals
the packet with its checksum.
"""

from dataclasses import dataclass

from . import codebook
from .packet import (
    LITERAL_MAX_CHARS,
    PROTOCOL_VERSION,
    compute_checksum,
    is_int,
    serialize,
)


@dataclass
class LineItem:
    """One line of a checkout intent.

    `item` may be a codebook item code ("MLK1") or the exact codebook
    display name ("Whole milk 1 gal"); the encoder resolves names to codes.
    `unit_price_cents` must be a non-negative integer number of cents.
    """

    item: str
    qty: int
    unit_price_cents: int


@dataclass
class Mandate:
    """Buyer spending mandate. The authoritative copy is pinned on the
    buyer's device (see decoder.DeviceContext); the packet header carries
    a claim that the decoder checks against the pinned copy.

    cap_cents:         hard spending cap; a packet above it is blocked.
    categories:        allowed category codes; any item outside is blocked.
    ask_threshold_cents: totals above this (and at or under the cap) are
                       not auto-approved; they require explicit buyer
                       confirmation.
    """

    cap_cents: int
    categories: list
    ask_threshold_cents: int


@dataclass
class CheckoutIntent:
    """A structured checkout to be encoded as a packet."""

    merchant: str  # codebook merchant code
    items: list  # list[LineItem]
    mandate: Mandate
    currency: str = "USD"
    literal_text: str = None  # optional seller free text (literal lane)


def _resolve_item_code(item):
    if item in codebook.ITEMS:
        return item
    code = codebook.NAME_TO_CODE.get(item)
    if code is None:
        raise ValueError("unknown item (not a codebook code or name): %r" % (item,))
    return code


def compress(intent):
    """Encode a CheckoutIntent. Returns (wire_text, packet_dict).

    Raises ValueError on any input the format cannot represent exactly:
    unknown merchant/item/category codes, non-integer or negative amounts,
    zero or negative quantities, or over-length literal text. Encoding
    fails loudly rather than emitting a lossy packet.
    """
    if intent.merchant not in codebook.MERCHANTS:
        raise ValueError("unknown merchant code: %r" % (intent.merchant,))
    if not intent.items:
        raise ValueError("checkout must contain at least one line item")

    mandate = intent.mandate
    if not is_int(mandate.cap_cents) or mandate.cap_cents < 0:
        raise ValueError("mandate cap must be a non-negative integer (cents)")
    if not is_int(mandate.ask_threshold_cents) or mandate.ask_threshold_cents < 0:
        raise ValueError("mandate ask-threshold must be a non-negative integer (cents)")
    for cat in mandate.categories:
        if not isinstance(cat, str) or cat not in codebook.CATEGORIES:
            raise ValueError("unknown mandate category code: %r" % (cat,))

    rows = []
    total = 0
    for line in intent.items:
        code = _resolve_item_code(line.item)
        if not is_int(line.qty) or line.qty < 1:
            raise ValueError("quantity must be a positive integer: %r" % (line.qty,))
        if not is_int(line.unit_price_cents) or line.unit_price_cents < 0:
            raise ValueError(
                "unit price must be a non-negative integer (cents): %r"
                % (line.unit_price_cents,)
            )
        rows.append([code, line.qty, line.unit_price_cents])
        total += line.qty * line.unit_price_cents

    packet = {
        "v": PROTOCOL_VERSION,
        "cb": codebook.CODEBOOK_VERSION,
        "m": intent.merchant,
        "cur": intent.currency,
        "md": {
            "cap": mandate.cap_cents,
            "cats": list(mandate.categories),
            "ask": mandate.ask_threshold_cents,
        },
        "it": rows,
        "tot": total,
    }
    if intent.literal_text is not None:
        if not isinstance(intent.literal_text, str):
            raise ValueError("literal text must be a string")
        if len(intent.literal_text) > LITERAL_MAX_CHARS:
            raise ValueError(
                "literal text exceeds the %d-character cap" % LITERAL_MAX_CHARS
            )
        packet["lit"] = intent.literal_text

    packet["ck"] = compute_checksum(packet)
    wire = serialize(packet)
    return wire, packet


def wire_size(wire):
    """Size of a wire packet in bytes (UTF-8)."""
    return len(wire.encode("utf-8"))
