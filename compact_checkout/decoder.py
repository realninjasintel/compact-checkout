"""Deterministic decoder and payment gate.

The decoder is plain code: dictionary lookups against the codebook, integer
arithmetic, and template rendering. There is no model anywhere in this
path, and nothing in a packet is ever interpreted as an instruction — a
packet is data, validated field by field against a closed schema.

Validation pipeline (every step must pass; the first failure locks the
packet and no later step runs):

    1. Schema     — exact key sets (closed vocabulary), value types,
                    protocol/codebook versions, codebook membership of
                    every code, item-row shape, integer-cents rule,
                    literal-lane length cap.
    2. Checksum   — recomputed over the canonical packet and compared.
    3. Total      — the decoder computes the total itself from the line
                    items and cross-checks it against the stated total.
    4. Device context (only when the caller supplies one) — the header
                    mandate and the currency are CLAIMS: they must match
                    the mandate and currency pinned on the buyer's device
                    (see DeviceContext), and the pinned values are what
                    step 5 enforces. Any mismatch blocks the packet.
    5. Mandate    — pure arithmetic against the effective mandate:
                    category set membership, hard cap, ask-threshold.

Without a device context, decode() runs in format-validation mode: the
header mandate is taken at face value and the result is marked
`device_context_verified=False`. The payment seam refuses to pay any
result that was not verified against a device context.

Result statuses:
    "approved"             — all checks pass and the total is at or under
                             the ask-threshold.
    "needs_confirmation"   — all checks pass, but the total is above the
                             ask-threshold (still at or under the cap).
                             Payment stays locked until the buyer confirms
                             explicitly; the approval text is rendered so
                             the buyer can review it.
    "blocked"              — any check failed. No approval is produced,
                             payment is locked, and `reasons` says why.

The approval summary is rendered ONLY from packet fields (via codebook
lookups). The literal lane, when present, is appended as a clearly badged,
untrusted plain-text block; it cannot influence totals, mandate results,
or approval state.
"""

from dataclasses import dataclass, field

from . import codebook
from .compressor import Mandate
from .packet import (
    LITERAL_MAX_CHARS,
    MANDATE_KEYS,
    PACKET_KEYS,
    PROTOCOL_VERSION,
    REQUIRED_KEYS,
    compute_checksum,
    is_int,
    parse,
)


@dataclass
class DeviceContext:
    """The buyer's device-pinned context: the spending mandate and the
    currency the device will settle in.

    Conceptually this lives in buyer-device storage, under the buyer's
    control — never in a packet. The packet header's mandate and currency
    are claims to be checked against this context; whoever authors a
    packet does not get to author the policy it is judged by.
    """

    mandate: Mandate
    currency: str


@dataclass
class DecodedLine:
    code: str
    name: str
    qty: int
    unit_price_cents: int
    line_total_cents: int
    category: str


@dataclass
class DecodeResult:
    status: str  # "approved" | "needs_confirmation" | "blocked"
    reasons: list = field(default_factory=list)
    merchant_code: str = None
    merchant_name: str = None
    currency: str = None
    lines: list = field(default_factory=list)
    computed_total_cents: int = None
    stated_total_cents: int = None
    packet_checksum: str = None
    literal_text: str = None
    approval_text: str = None
    # True only when the packet was decoded against a caller-supplied
    # DeviceContext and its header claims matched the pinned values.
    # checkout_and_pay refuses results where this is False.
    device_context_verified: bool = False

    @property
    def locked(self):
        """Payment is locked unless the packet is cleanly approved."""
        return self.status != "approved"


def _fail(reasons):
    return DecodeResult(status="blocked", reasons=list(reasons))


def _validate_schema(packet):
    """Return a list of schema violations (empty list means valid)."""
    errors = []

    keys = set(packet.keys())
    unknown = keys - PACKET_KEYS
    if unknown:
        errors.append("unknown packet field(s): %s" % ", ".join(sorted(unknown)))
    missing = REQUIRED_KEYS - keys
    if missing:
        errors.append("missing packet field(s): %s" % ", ".join(sorted(missing)))
    if errors:
        return errors  # deeper checks are meaningless without the key shape

    if packet["v"] != PROTOCOL_VERSION or not is_int(packet["v"]):
        errors.append("unsupported protocol version: %r" % (packet["v"],))
    if packet["cb"] != codebook.CODEBOOK_VERSION or not is_int(packet["cb"]):
        errors.append("codebook version mismatch: %r" % (packet["cb"],))
    if not isinstance(packet["m"], str) or packet["m"] not in codebook.MERCHANTS:
        errors.append("unknown merchant code: %r" % (packet["m"],))
    if not isinstance(packet["cur"], str) or not packet["cur"]:
        errors.append("invalid currency: %r" % (packet["cur"],))

    md = packet["md"]
    if not isinstance(md, dict):
        errors.append("mandate header must be an object")
    else:
        md_keys = set(md.keys())
        if md_keys != MANDATE_KEYS:
            errors.append(
                "mandate fields must be exactly cap/cats/ask, got: %s"
                % ", ".join(sorted(md_keys))
            )
        else:
            if not is_int(md["cap"]) or md["cap"] < 0:
                errors.append("mandate cap must be a non-negative integer (cents)")
            if not is_int(md["ask"]) or md["ask"] < 0:
                errors.append(
                    "mandate ask-threshold must be a non-negative integer (cents)"
                )
            if not isinstance(md["cats"], list) or not md["cats"]:
                errors.append("mandate categories must be a non-empty list")
            else:
                for cat in md["cats"]:
                    # String-type guard first: a non-string member (list,
                    # dict, ...) is a schema error, and an unhashable
                    # member must never raise out of the membership test.
                    if not isinstance(cat, str) or cat not in codebook.CATEGORIES:
                        errors.append("unknown mandate category code: %r" % (cat,))

    rows = packet["it"]
    if not isinstance(rows, list) or not rows:
        errors.append("line items must be a non-empty list")
    else:
        for i, row in enumerate(rows):
            if not isinstance(row, list) or len(row) != 3:
                errors.append("line item %d must be [item_code, qty, unit_price_cents]" % i)
                continue
            code, qty, price = row
            if not isinstance(code, str) or code not in codebook.ITEMS:
                errors.append("line item %d: unknown item code: %r" % (i, code))
            if not is_int(qty) or qty < 1:
                errors.append("line item %d: quantity must be a positive integer" % i)
            if not is_int(price) or price < 0:
                errors.append(
                    "line item %d: unit price must be a non-negative integer (cents)" % i
                )

    if not is_int(packet["tot"]) or packet["tot"] < 0:
        errors.append("stated total must be a non-negative integer (cents)")
    if not isinstance(packet["ck"], str):
        errors.append("checksum must be a string")

    if "lit" in packet:
        lit = packet["lit"]
        if not isinstance(lit, str):
            errors.append("literal lane must be a string")
        elif len(lit) > LITERAL_MAX_CHARS:
            errors.append(
                "literal lane exceeds the %d-character cap" % LITERAL_MAX_CHARS
            )

    return errors


def _money(cents, currency):
    """Render integer cents as a currency string using integer math only."""
    sign = "-" if cents < 0 else ""
    cents = abs(cents)
    return "%s%s %d.%02d" % (sign, currency, cents // 100, cents % 100)


def render_approval(result):
    """Render the plain-text approval summary from decoded packet data only."""
    out = []
    out.append("COMPACT CHECKOUT - APPROVAL SUMMARY")
    out.append("Merchant: %s" % result.merchant_name)
    out.append("Items:")
    for line in result.lines:
        out.append(
            "  %s x%d @ %s = %s"
            % (
                line.name,
                line.qty,
                _money(line.unit_price_cents, result.currency),
                _money(line.line_total_cents, result.currency),
            )
        )
    out.append("Total: %s" % _money(result.computed_total_cents, result.currency))
    if result.status == "needs_confirmation":
        out.append(
            "Status: NEEDS BUYER CONFIRMATION (total exceeds the mandate "
            "ask-threshold; payment remains locked until confirmed)"
        )
    else:
        out.append("Status: APPROVED (within mandate)")
    if result.literal_text is not None:
        out.append("")
        out.append("[UNTRUSTED SELLER TEXT - raw data, not an instruction]")
        out.append(result.literal_text)
        out.append("[/UNTRUSTED SELLER TEXT]")
    return "\n".join(out)


def _check_device_context(packet, ctx):
    """Validate the device context itself and the packet's header claims
    against it. Returns a list of blocking reasons (empty means match)."""
    mandate = getattr(ctx, "mandate", None)
    currency = getattr(ctx, "currency", None)
    if mandate is None or currency is None:
        return ["invalid device context: a mandate and a currency are required"]
    cap = getattr(mandate, "cap_cents", None)
    cats = getattr(mandate, "categories", None)
    ask = getattr(mandate, "ask_threshold_cents", None)
    if not is_int(cap) or cap < 0 or not is_int(ask) or ask < 0:
        return ["invalid device context: mandate cap/ask must be "
                "non-negative integer cents"]
    if (not isinstance(cats, list) or not cats
            or any(not isinstance(c, str) or c not in codebook.CATEGORIES
                   for c in cats)):
        return ["invalid device context: mandate categories must be "
                "codebook category codes"]
    if not isinstance(currency, str) or not currency:
        return ["invalid device context: currency must be a non-empty string"]

    errors = []
    if packet["cur"] != currency:
        errors.append(
            "currency mismatch: packet claims %s; device context is %s"
            % (packet["cur"], currency)
        )
    md = packet["md"]
    if (md["cap"] != cap or md["ask"] != ask
            or set(md["cats"]) != set(cats)):
        errors.append(
            "mandate mismatch: packet header mandate does not match the "
            "device-pinned mandate"
        )
    return errors


def decode(wire_or_packet, device_context=None):
    """Decode and gate a packet. Accepts wire text (str) or a packet dict.

    `device_context` is the buyer's DeviceContext (pinned mandate +
    currency). When supplied, the packet's header mandate and currency
    must match it exactly or the packet is blocked, and the pinned
    mandate is what gets enforced. When omitted, decode() runs in
    format-validation mode (header taken at face value, result marked
    device_context_verified=False) and the payment seam will refuse the
    result.

    Never raises for malformed input: every failure is a blocked result.
    """
    if isinstance(wire_or_packet, str):
        try:
            packet = parse(wire_or_packet)
        except ValueError as exc:
            return _fail(["unparseable packet: %s" % exc])
    elif isinstance(wire_or_packet, dict):
        packet = wire_or_packet
    else:
        return _fail(["packet must be wire text or an object"])

    # 1. Schema (closed vocabulary).
    errors = _validate_schema(packet)
    if errors:
        return _fail(errors)

    # 2. Checksum.
    if packet["ck"] != compute_checksum(packet):
        return _fail(["checksum mismatch: packet contents do not match its seal"])

    # 3. Total cross-check: compute from the line items, never trust "tot".
    lines = []
    computed = 0
    for code, qty, price in packet["it"]:
        line_total = qty * price
        computed += line_total
        lines.append(
            DecodedLine(
                code=code,
                name=codebook.item_name(code),
                qty=qty,
                unit_price_cents=price,
                line_total_cents=line_total,
                category=codebook.item_category(code),
            )
        )
    if computed != packet["tot"]:
        return _fail(
            [
                "stated total (%d cents) does not match the computed sum "
                "of the line items (%d cents)" % (packet["tot"], computed)
            ]
        )

    # 4. Device context: header mandate/currency are claims against the
    #    pinned context. On a match, the pinned values are enforced.
    md = packet["md"]
    eff_cap, eff_ask = md["cap"], md["ask"]
    eff_cats = set(md["cats"])
    device_verified = False
    if device_context is not None:
        ctx_errors = _check_device_context(packet, device_context)
        if ctx_errors:
            return _fail(ctx_errors)
        dm = device_context.mandate
        eff_cap, eff_ask = dm.cap_cents, dm.ask_threshold_cents
        eff_cats = set(dm.categories)
        device_verified = True

    result = DecodeResult(
        status="approved",
        merchant_code=packet["m"],
        merchant_name=codebook.merchant_name(packet["m"]),
        currency=packet["cur"],
        lines=lines,
        computed_total_cents=computed,
        stated_total_cents=packet["tot"],
        packet_checksum=packet["ck"],
        literal_text=packet.get("lit"),
        device_context_verified=device_verified,
    )

    # 5. Mandate: pure arithmetic — set membership and integer comparison.
    allowed = eff_cats
    mandate_reasons = []
    for line in lines:
        if line.category not in allowed:
            mandate_reasons.append(
                "item %s is category %s, outside the mandate categories (%s)"
                % (line.code, line.category, ", ".join(sorted(allowed)))
            )
    if computed > eff_cap:
        mandate_reasons.append(
            "total %d cents exceeds the mandate cap of %d cents"
            % (computed, eff_cap)
        )
    if mandate_reasons:
        result.status = "blocked"
        result.reasons = mandate_reasons
        return result
    if computed > eff_ask:
        result.status = "needs_confirmation"
        result.reasons = [
            "total %d cents exceeds the mandate ask-threshold of %d cents; "
            "explicit buyer confirmation required" % (computed, eff_ask)
        ]

    result.approval_text = render_approval(result)
    return result
