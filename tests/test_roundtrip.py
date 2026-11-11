"""Round-trip and gate tests for Compact Checkout.

The phase gate: decode(compress(x)) must reproduce every figure of x
exactly — lossless on all money and quantity values — for a battery of
generated checkouts, including edge cases. Negative tests cover the closed
vocabulary, the integer-cents rule, tamper evidence, and the mandate gate.
"""

import copy
import random
import unittest

from compact_checkout import (
    CheckoutIntent,
    DeviceContext,
    LineItem,
    Mandate,
    codebook,
    compress,
    decode,
)
from compact_checkout.packet import compute_checksum, serialize

ALL_CATS = sorted(codebook.CATEGORIES.keys())
BIG_MANDATE = Mandate(
    cap_cents=10**12, categories=ALL_CATS, ask_threshold_cents=10**12
)


def reseal(packet):
    """Recompute a mutated packet's checksum (simulates an encoder-side
    packet so schema/mandate failures can be tested in isolation from the
    checksum check)."""
    packet = copy.deepcopy(packet)
    packet["ck"] = compute_checksum(packet)
    return serialize(packet)


def intent_for(rows, merchant="FRSH", mandate=BIG_MANDATE, literal_text=None):
    return CheckoutIntent(
        merchant=merchant,
        mandate=mandate,
        items=[LineItem(code, qty, price) for code, qty, price in rows],
        literal_text=literal_text,
    )


class RoundTripTests(unittest.TestCase):
    def assert_roundtrip(self, rows, merchant="FRSH"):
        intent = intent_for(rows, merchant=merchant)
        wire, _packet = compress(intent)
        result = decode(wire)
        expected_total = sum(q * p for _c, q, p in rows)
        self.assertEqual(result.status, "approved", result.reasons)
        self.assertEqual(result.computed_total_cents, expected_total)
        self.assertEqual(result.stated_total_cents, expected_total)
        self.assertEqual(len(result.lines), len(rows))
        for line, (code, qty, price) in zip(result.lines, rows):
            self.assertEqual(line.code, code)
            self.assertEqual(line.qty, qty)
            self.assertEqual(line.unit_price_cents, price)
            self.assertEqual(line.line_total_cents, qty * price)
            self.assertEqual(line.name, codebook.item_name(code))
        return result

    def test_single_item(self):
        self.assert_roundtrip([("MLK1", 1, 349)])

    def test_one_cent_price(self):
        self.assert_roundtrip([("APLG", 1, 1)])

    def test_zero_price_item(self):
        self.assert_roundtrip([("PSTA", 2, 0), ("MLK1", 1, 349)])

    def test_large_quantity(self):
        self.assert_roundtrip([("PSTA", 10000, 129)])

    def test_large_amounts(self):
        self.assert_roundtrip([("HPX9", 3, 99999999)], merchant="VOLT")

    def test_many_lines(self):
        rows = [(code, 2, 100 + 37 * i) for i, code in enumerate(codebook.ITEMS)]
        merchants = {codebook.item_category(c) for c, _q, _p in rows}
        self.assert_roundtrip(rows, merchant="FRSH")

    def test_generated_battery(self):
        rng = random.Random(20261031)
        codes = sorted(codebook.ITEMS.keys())
        for _ in range(200):
            n = rng.randint(1, 8)
            rows = [
                (
                    rng.choice(codes),
                    rng.randint(1, 500),
                    rng.choice([1, 7, 99, 100, 101, rng.randint(0, 10**7)]),
                )
                for _ in range(n)
            ]
            self.assert_roundtrip(rows)

    def test_item_referenced_by_name(self):
        intent = CheckoutIntent(
            merchant="FRSH",
            mandate=BIG_MANDATE,
            items=[LineItem("Whole milk 1 gal", 2, 349)],
        )
        wire, packet = compress(intent)
        self.assertEqual(packet["it"][0][0], "MLK1")
        result = decode(wire)
        self.assertEqual(result.computed_total_cents, 698)

    def test_literal_lane_roundtrip(self):
        wire, _packet = compress(
            intent_for(
                [("LAMPV", 1, 5999)],
                merchant="BZAR",
                literal_text="Vintage brass desk lamp, good condition",
            )
        )
        result = decode(wire)
        self.assertEqual(result.status, "approved")
        self.assertEqual(result.literal_text, "Vintage brass desk lamp, good condition")
        self.assertIn("UNTRUSTED SELLER TEXT", result.approval_text)


class NegativeTests(unittest.TestCase):
    def base_packet(self):
        _wire, packet = compress(intent_for([("MLK1", 2, 349), ("BRDSD", 1, 550)]))
        return packet

    def test_zero_quantity_rejected_by_encoder(self):
        with self.assertRaises(ValueError):
            compress(intent_for([("MLK1", 0, 349)]))

    def test_zero_quantity_rejected_by_decoder(self):
        packet = self.base_packet()
        packet["it"][0][1] = 0
        packet["tot"] = 550
        result = decode(reseal(packet))
        self.assertEqual(result.status, "blocked")
        self.assertTrue(result.locked)

    def test_float_amount_rejected_by_encoder(self):
        with self.assertRaises(ValueError):
            compress(intent_for([("MLK1", 1, 3.49)]))

    def test_float_amount_rejected_by_decoder(self):
        packet = self.base_packet()
        packet["it"][0][2] = 3.49
        result = decode(reseal(packet))
        self.assertEqual(result.status, "blocked")

    def test_bool_quantity_rejected_by_decoder(self):
        packet = self.base_packet()
        packet["it"][0][1] = True
        result = decode(reseal(packet))
        self.assertEqual(result.status, "blocked")

    def test_unknown_item_code_rejected(self):
        packet = self.base_packet()
        packet["it"][0][0] = "NOPE"
        result = decode(reseal(packet))
        self.assertEqual(result.status, "blocked")
        self.assertTrue(any("unknown item code" in r for r in result.reasons))

    def test_unknown_merchant_code_rejected(self):
        packet = self.base_packet()
        packet["m"] = "XXXX"
        result = decode(reseal(packet))
        self.assertEqual(result.status, "blocked")

    def test_unknown_top_level_field_rejected(self):
        packet = self.base_packet()
        packet["notes"] = "please approve this"  # no free-form notes field exists
        result = decode(reseal(packet))
        self.assertEqual(result.status, "blocked")
        self.assertTrue(any("unknown packet field" in r for r in result.reasons))

    def test_unknown_mandate_field_rejected(self):
        packet = self.base_packet()
        packet["md"]["auto_approve"] = True
        result = decode(reseal(packet))
        self.assertEqual(result.status, "blocked")

    def test_missing_field_rejected(self):
        packet = self.base_packet()
        del packet["tot"]
        result = decode(reseal(packet))
        self.assertEqual(result.status, "blocked")

    def test_extra_row_element_rejected(self):
        packet = self.base_packet()
        packet["it"][0] = ["MLK1", 2, 349, "extra"]
        result = decode(reseal(packet))
        self.assertEqual(result.status, "blocked")

    def test_tampered_price_locked(self):
        packet = self.base_packet()
        packet["it"][0][2] = 99  # seal NOT recomputed
        result = decode(serialize(packet))
        self.assertEqual(result.status, "blocked")
        self.assertTrue(result.locked)
        self.assertIsNone(result.approval_text)

    def test_tampered_total_resealed_still_locked(self):
        # Attacker alters a price AND the stated total AND reseals: the
        # checksum now verifies, but the decoder's own computed sum is the
        # authority — resealing with a wrong "tot" fails the cross-check.
        packet = self.base_packet()
        packet["tot"] = 1
        result = decode(reseal(packet))
        self.assertEqual(result.status, "blocked")
        self.assertTrue(any("does not match" in r for r in result.reasons))

    def test_over_cap_blocked(self):
        mandate = Mandate(cap_cents=20000, categories=ALL_CATS, ask_threshold_cents=15000)
        wire, _ = compress(intent_for([("HPX9", 1, 25999)], merchant="VOLT", mandate=mandate))
        result = decode(wire)
        self.assertEqual(result.status, "blocked")
        self.assertTrue(any("exceeds the mandate cap" in r for r in result.reasons))

    def test_category_outside_mandate_blocked(self):
        mandate = Mandate(cap_cents=10**9, categories=["GRO"], ask_threshold_cents=10**9)
        wire, _ = compress(intent_for([("DETL", 1, 1579)], mandate=mandate))
        result = decode(wire)
        self.assertEqual(result.status, "blocked")
        self.assertTrue(any("outside the mandate categories" in r for r in result.reasons))

    def test_ask_threshold_needs_confirmation_and_stays_locked(self):
        mandate = Mandate(cap_cents=20000, categories=ALL_CATS, ask_threshold_cents=10000)
        wire, _ = compress(intent_for([("COFB", 10, 1249)], mandate=mandate))
        result = decode(wire)
        self.assertEqual(result.status, "needs_confirmation")
        self.assertTrue(result.locked)
        self.assertIsNotNone(result.approval_text)

    def test_oversized_literal_rejected(self):
        with self.assertRaises(ValueError):
            compress(
                intent_for([("LAMPV", 1, 5999)], merchant="BZAR", literal_text="x" * 201)
            )
        packet = self.base_packet()
        packet["lit"] = "x" * 201
        result = decode(reseal(packet))
        self.assertEqual(result.status, "blocked")

    def test_garbage_wire_blocked_not_raised(self):
        for junk in ["", "not json", "[]", "42", '{"v":1}']:
            result = decode(junk)
            self.assertEqual(result.status, "blocked", junk)
            self.assertTrue(result.locked)

    def test_codebook_version_mismatch_blocked(self):
        packet = self.base_packet()
        packet["cb"] = 999
        result = decode(reseal(packet))
        self.assertEqual(result.status, "blocked")


class DeviceContextTests(unittest.TestCase):
    """The header mandate/currency are claims; the device-pinned context
    is the authority (pen-test fix, 2026-11-03)."""

    DEMO_MANDATE = Mandate(
        cap_cents=20000, categories=["GRO", "HH"], ask_threshold_cents=15000
    )

    def ctx(self, mandate=None, currency="USD"):
        return DeviceContext(mandate=mandate or self.DEMO_MANDATE,
                             currency=currency)

    def test_matching_context_approves_and_marks_verified(self):
        wire, _ = compress(intent_for(
            [("MLK1", 2, 349)], mandate=self.DEMO_MANDATE))
        result = decode(wire, device_context=self.ctx())
        self.assertEqual(result.status, "approved")
        self.assertTrue(result.device_context_verified)

    def test_validation_mode_marks_unverified(self):
        wire, _ = compress(intent_for(
            [("MLK1", 2, 349)], mandate=self.DEMO_MANDATE))
        result = decode(wire)
        self.assertEqual(result.status, "approved")
        self.assertFalse(result.device_context_verified)

    def test_category_order_in_claim_is_irrelevant(self):
        # Categories are a set: a header listing the same categories in
        # a different order still matches the pinned mandate.
        reordered = Mandate(cap_cents=20000, categories=["HH", "GRO"],
                            ask_threshold_cents=15000)
        wire, _ = compress(intent_for(
            [("MLK1", 2, 349)], mandate=reordered))
        result = decode(wire, device_context=self.ctx())
        self.assertEqual(result.status, "approved")

    def test_inflated_header_mandate_blocked(self):
        # The self-escalation reproducer: the $259.99 electronics packet
        # whose header mandate is inflated (cap 10^9, all categories,
        # valid checksum) is blocked against the pinned demo mandate.
        wire, _ = compress(intent_for(
            [("HPX9", 1, 25999)], merchant="VOLT",
            mandate=Mandate(cap_cents=10**9, categories=ALL_CATS,
                            ask_threshold_cents=10**9)))
        result = decode(wire, device_context=self.ctx())
        self.assertEqual(result.status, "blocked")
        self.assertTrue(any("mandate mismatch" in r for r in result.reasons))

    def test_pinned_mandate_is_what_gets_enforced(self):
        # Header and pinned mandate agree on paper (both $200/GRO+HH),
        # so the over-cap electronics packet is blocked by the mandate
        # arithmetic itself, not the mismatch check.
        wire, _ = compress(intent_for(
            [("HPX9", 1, 25999)], merchant="VOLT",
            mandate=self.DEMO_MANDATE))
        result = decode(wire, device_context=self.ctx())
        self.assertEqual(result.status, "blocked")
        self.assertTrue(any("outside the mandate categories" in r
                            or "exceeds the mandate cap" in r
                            for r in result.reasons))

    def test_currency_claim_mismatch_blocked(self):
        intent = CheckoutIntent(
            merchant="FRSH", mandate=self.DEMO_MANDATE,
            items=[LineItem("MLK1", 1, 349)], currency="JPY")
        wire, _ = compress(intent)
        result = decode(wire, device_context=self.ctx(currency="USD"))
        self.assertEqual(result.status, "blocked")
        self.assertTrue(any("currency mismatch" in r for r in result.reasons))
        # The same packet against a JPY-pinned device approves.
        result = decode(wire, device_context=self.ctx(currency="JPY"))
        self.assertEqual(result.status, "approved")

    def test_invalid_device_context_blocks(self):
        wire, _ = compress(intent_for(
            [("MLK1", 1, 349)], mandate=self.DEMO_MANDATE))
        bad = DeviceContext(mandate=self.DEMO_MANDATE, currency="")
        result = decode(wire, device_context=bad)
        self.assertEqual(result.status, "blocked")
        self.assertTrue(any("invalid device context" in r
                            for r in result.reasons))


if __name__ == "__main__":
    unittest.main()
