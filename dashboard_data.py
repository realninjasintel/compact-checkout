#!/usr/bin/env python3
"""Dashboard data generator for Compact Checkout.

Emits the token-savings data behind ui/dashboard.html as JSON:
ui/dashboard-data.json, plus ui/dashboard-data.js (the same payload as a
script assignment, so the dashboard also opens from file://).

Every figure is measured with tiktoken (o200k_base) on the real wire
packets produced by the compressor — the same prose rendering as
measure.py. If tiktoken is unavailable this script fails loudly rather
than emitting estimated numbers.

Rows:
  scenarios — the four frozen demo scenarios (prose tokens, packet
              tokens, tokens saved, ratio, decoder verdict, amount).
  sweep     — generated grocery baskets of 1..40 line items through the
              real compressor, showing how the ratio scales with size.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import tiktoken
except ImportError:
    sys.exit("tiktoken is required: dashboard figures are measured, never estimated")

from compact_checkout import CheckoutIntent, LineItem, Mandate, compress, decode  # noqa: E402
from measure import prose_rendering  # noqa: E402
from scenarios import SCENARIOS, scenario_1_grocery  # noqa: E402

_ENC = tiktoken.get_encoding("o200k_base")
METHOD = "tiktoken o200k_base (measured)"

UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")

SWEEP_SIZES = [1, 3, 5, 10, 20, 40]
SWEEP_MANDATE = Mandate(
    cap_cents=10**9, categories=["GRO", "HH"], ask_threshold_cents=10**9
)


def count_tokens(text):
    return len(_ENC.encode(text))


def money(cents):
    return "$%d.%02d" % (cents // 100, cents % 100)


def measure_packet(wire, packet, result):
    """Token figures for one compressed checkout."""
    prose_tokens = count_tokens(prose_rendering(packet))
    packet_tokens = count_tokens(wire)
    amount_cents = (
        result.computed_total_cents
        if result.computed_total_cents is not None
        else packet["tot"]
    )
    return {
        "items": len(packet["it"]),
        "prose_tokens": prose_tokens,
        "packet_tokens": packet_tokens,
        "tokens_saved": prose_tokens - packet_tokens,
        "ratio": round(prose_tokens / packet_tokens, 2) if packet_tokens else None,
        "verdict": result.status,
        "amount": money(amount_cents),
        "amount_cents": amount_cents,
    }


def scenario_rows():
    rows = []
    for label, build, _expected in SCENARIOS:
        wire, packet, result = build()
        row = measure_packet(wire, packet, result)
        row["scenario"] = label.split(". ", 1)[-1]
        row["checksum"] = packet["ck"]
        rows.append(row)
    return rows


def sweep_rows():
    """Baskets of N line items, cycling the grocery scenario's item pool.

    Repeat passes raise the quantity so no two rows are identical.
    """
    _wire, pool_packet, _result = scenario_1_grocery()
    pool = pool_packet["it"]  # [[code, qty, unit_price_cents], ...]
    rows = []
    for size in SWEEP_SIZES:
        items = []
        for i in range(size):
            code, qty, price = pool[i % len(pool)]
            items.append(LineItem(code, qty + (i // len(pool)), price))
        intent = CheckoutIntent(
            merchant="FRSH", mandate=SWEEP_MANDATE, items=items
        )
        wire, packet = compress(intent)
        rows.append(measure_packet(wire, packet, decode(wire)))
    return rows


def build_data():
    scenarios = scenario_rows()
    sweep = sweep_rows()
    flagship = next(r for r in scenarios if r["scenario"].startswith("Grocery"))
    total_prose = sum(r["prose_tokens"] for r in scenarios)
    total_packet = sum(r["packet_tokens"] for r in scenarios)
    return {
        "method": METHOD,
        "summary": {
            "flagship_scenario": flagship["scenario"],
            "flagship_ratio": flagship["ratio"],
            "flagship_prose_tokens": flagship["prose_tokens"],
            "flagship_packet_tokens": flagship["packet_tokens"],
            "total_prose_tokens": total_prose,
            "total_packet_tokens": total_packet,
            "total_tokens_saved": total_prose - total_packet,
            "best_sweep_ratio": sweep[-1]["ratio"],
            "best_sweep_items": sweep[-1]["items"],
        },
        "scenarios": scenarios,
        "sweep": sweep,
    }


def main():
    data = build_data()
    payload = json.dumps(data, indent=2)
    json_path = os.path.join(UI_DIR, "dashboard-data.json")
    js_path = os.path.join(UI_DIR, "dashboard-data.js")
    with open(json_path, "w") as fh:
        fh.write(payload + "\n")
    with open(js_path, "w") as fh:
        fh.write("window.DASHBOARD_DATA = ")
        fh.write(payload)
        fh.write(";\n")

    print("Token counting method: %s" % data["method"])
    print()
    print("%-46s %6s %10s %10s %8s %7s  %s" % ("Scenario", "Items", "Prose", "Packet", "Saved", "Ratio", "Verdict"))
    print("-" * 108)
    for r in data["scenarios"]:
        print(
            "%-46s %6d %10d %10d %8d %6.2fx  %s"
            % (r["scenario"], r["items"], r["prose_tokens"], r["packet_tokens"], r["tokens_saved"], r["ratio"], r["verdict"])
        )
    print()
    print("%-46s %6s %10s %10s %8s %7s  %s" % ("Basket sweep", "Items", "Prose", "Packet", "Saved", "Ratio", "Verdict"))
    print("-" * 108)
    for r in data["sweep"]:
        print(
            "%-46s %6d %10d %10d %8d %6.2fx  %s"
            % ("", r["items"], r["prose_tokens"], r["packet_tokens"], r["tokens_saved"], r["ratio"], r["verdict"])
        )
    print()
    print("Wrote %s" % json_path)
    print("Wrote %s" % js_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
