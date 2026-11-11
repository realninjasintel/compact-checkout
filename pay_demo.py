#!/usr/bin/env python3
"""End-to-end run: decode each scenario, pay the approved ones via the
mock PayPal adapter, and show that blocked packets never reach payment."""

import sys

from compact_checkout import MockPayPalAdapter, PaymentRefused, checkout_and_pay
from scenarios import SCENARIOS


def main():
    failures = 0
    for title, build, expected in SCENARIOS:
        _wire, _packet, result = build()
        print("=" * 72)
        print(title)
        print("  gate: %s" % result.status.upper())
        adapter = MockPayPalAdapter()
        try:
            receipt = checkout_and_pay(result, adapter, buyer_confirmed=True)
        except PaymentRefused:
            print("  payment: not reached (gate refusal)")
            if adapter.calls:
                failures += 1
                print("  ERROR: adapter received calls for a gated packet")
            continue
        if receipt.status == "captured":
            print(
                "  payment: captured - order %s - transaction %s - packet %s"
                % (receipt.order_id, receipt.transaction_id, receipt.packet_checksum)
            )
        else:
            failures += 1
            print("  payment: FAILED - %s" % receipt.reason)
        print()
    print("=" * 72)
    if failures:
        print("PAY DEMO RESULT: %d failure(s)." % failures)
        return 1
    print("PAY DEMO RESULT: approved packets paid; blocked packets never reached payment.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
