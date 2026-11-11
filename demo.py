#!/usr/bin/env python3
"""Run the four Compact Checkout demo scenarios and print the gate outcome,
the wire packet, and (when approved) the rendered approval summary."""

import sys

from compact_checkout import wire_size
from scenarios import SCENARIOS


def main():
    failures = 0
    for title, build, expected in SCENARIOS:
        wire, _packet, result = build()
        ok = result.status == expected
        failures += 0 if ok else 1
        print("=" * 72)
        print("%s" % title)
        print("  wire packet (%d bytes): %s" % (wire_size(wire), wire))
        print(
            "  gate: %s (expected %s) %s"
            % (result.status.upper(), expected.upper(), "OK" if ok else "MISMATCH")
        )
        if result.computed_total_cents is not None:
            print("  computed total: %d cents" % result.computed_total_cents)
        for reason in result.reasons:
            print("  reason: %s" % reason)
        if result.approval_text:
            print("-" * 72)
            print(result.approval_text)
        print()
    print("=" * 72)
    if failures:
        print("DEMO RESULT: %d scenario outcome(s) did not match expectations." % failures)
        return 1
    print("DEMO RESULT: all 4 scenarios produced the expected gate outcome.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
