#!/usr/bin/env python3
"""Token measurement harness for Compact Checkout.

For each demo scenario, counts tokens for:
  (a) a natural, verbose agent-prose rendering of the same checkout — the
      narration a prose-based agent pipeline would generate and transmit;
  (b) the minified wire packet that carries the same checkout.

Tokenizer: uses tiktoken (o200k_base) when the package is available. When
it is not, falls back to a characters/4 heuristic and LABELS every figure
as an estimate. The counting method is always printed with the table.
"""

import sys

sys.path.insert(0, ".")
from compact_checkout import codebook  # noqa: E402
from scenarios import scenario_1_grocery, scenario_2_over_cap, scenario_3_hostile_listing  # noqa: E402

try:
    import tiktoken

    _ENC = tiktoken.get_encoding("o200k_base")
    METHOD = "tiktoken o200k_base (measured)"

    def count_tokens(text):
        return len(_ENC.encode(text))

except Exception:
    METHOD = "ESTIMATE ONLY: characters/4 (tiktoken unavailable)"

    def count_tokens(text):
        return round(len(text) / 4)


def money(cents):
    return "$%d.%02d" % (cents // 100, cents % 100)


def prose_rendering(packet):
    """Render a packet's checkout as verbose agent prose."""
    merchant = codebook.merchant_name(packet["m"])
    parts = [
        "Here's the checkout I've prepared for you at %s. "
        "I went through the order item by item, and here is everything "
        "that is included:" % merchant
    ]
    for code, qty, price in packet["it"]:
        name = codebook.item_name(code)
        parts.append(
            "%d x %s at %s each, which comes to %s"
            % (qty, name, money(price), money(qty * price))
        )
    if "lit" in packet:
        parts.append('The seller\'s listing title reads: "%s"' % packet["lit"])
    parts.append(
        "Adding all of that up, the grand total for this order is %s. "
        "Your spending mandate allows up to %s for this kind of purchase, "
        "so please take a look, confirm everything looks right, and "
        "approve the payment to complete the order."
        % (money(packet["tot"]), money(packet["md"]["cap"]))
    )
    return " ".join(parts)


def main():
    cases = [
        ("1. Grocery checkout", scenario_1_grocery),
        ("2. Electronics order", scenario_2_over_cap),
        ("3. Hostile listing", scenario_3_hostile_listing),
    ]
    print("Token counting method: %s" % METHOD)
    print()
    print("%-22s %12s %12s %8s" % ("Scenario", "Prose", "Packet", "Ratio"))
    print("-" * 58)
    for label, build in cases:
        wire, packet, _result = build()
        prose = prose_rendering(packet)
        prose_tokens = count_tokens(prose)
        packet_tokens = count_tokens(wire)
        ratio = (prose_tokens / packet_tokens) if packet_tokens else float("nan")
        print(
            "%-22s %12d %12d %7.2fx"
            % (label, prose_tokens, packet_tokens, ratio)
        )
    print()
    print("Scenario 4 (tampered packet) is byte-identical in size to")
    print("scenario 1 by construction, so it is not a separate row.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
