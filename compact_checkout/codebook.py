"""Codebook v0 for Compact Checkout.

The codebook is the shared dictionary between the encoder (agent side) and
the decoder (buyer device). Item names, units, merchant names, and category
names live here, on both endpoints, and are never carried on the wire. A
packet carries only short codes; the codebook version travels in the packet
header so encoder and decoder can detect a version mismatch and fail closed.

All prices in this module and everywhere in the package are integer cents.
"""

CODEBOOK_VERSION = 1

# Category code -> human-readable category name.
CATEGORIES = {
    "GRO": "Groceries",
    "HH": "Household",
    "ELE": "Electronics",
    "MKT": "Marketplace",
}

# Merchant code -> human-readable merchant name.
MERCHANTS = {
    "FRSH": "FreshMart Grocery",
    "VOLT": "VoltEdge Electronics",
    "BZAR": "Open Bazaar Marketplace",
}

# Item code -> (display name, unit label, category code).
# The unit price is NOT stored here: prices are per-order facts and travel in
# the packet's verbatim lane as integer cents.
ITEMS = {
    # Groceries (merchant FRSH).
    "MLK1": ("Whole milk 1 gal", "each", "GRO"),
    "EGG12": ("Eggs 12 ct", "each", "GRO"),
    "BRDSD": ("Sourdough loaf", "each", "GRO"),
    "RICE5": ("Jasmine rice 5 lb", "each", "GRO"),
    "CHKNB": ("Chicken breast 1 lb", "each", "GRO"),
    "APLG": ("Gala apple", "each", "GRO"),
    "COFB": ("Coffee beans 12 oz", "each", "GRO"),
    "CHDR": ("Cheddar block 8 oz", "each", "GRO"),
    "OJ64": ("Orange juice 64 oz", "each", "GRO"),
    "PSTA": ("Pasta 16 oz", "each", "GRO"),
    "TSAU": ("Tomato sauce 24 oz", "each", "GRO"),
    "GYOG": ("Greek yogurt 32 oz", "each", "GRO"),
    "BTTR": ("Butter 8 oz", "each", "GRO"),
    # Household (merchant FRSH).
    "DETL": ("Laundry detergent 100 oz", "each", "HH"),
    "PTWL": ("Paper towels 2 ct", "each", "HH"),
    # Electronics (merchant VOLT).
    "HPX9": ("Wireless headphones X9", "each", "ELE"),
    "CBLU": ("USB-C cable 2 m", "each", "ELE"),
    "CHG65": ("USB-C charger 65 W", "each", "ELE"),
    # Marketplace (merchant BZAR). Listing titles for marketplace items are
    # seller-supplied free text and travel in the packet's literal lane, not
    # here; the codebook entry is the decoder's own neutral label.
    "LAMPV": ("Desk lamp (marketplace listing)", "each", "MKT"),
}

# Reverse lookup: exact display name -> item code (encoder side).
NAME_TO_CODE = {name: code for code, (name, _unit, _cat) in ITEMS.items()}


def item_name(code):
    """Return the display name for an item code, or None if unknown."""
    entry = ITEMS.get(code)
    return entry[0] if entry else None


def item_unit(code):
    """Return the unit label for an item code, or None if unknown."""
    entry = ITEMS.get(code)
    return entry[1] if entry else None


def item_category(code):
    """Return the category code for an item code, or None if unknown."""
    entry = ITEMS.get(code)
    return entry[2] if entry else None


def merchant_name(code):
    """Return the merchant display name for a code, or None if unknown."""
    return MERCHANTS.get(code)


def category_name(code):
    """Return the category display name for a code, or None if unknown."""
    return CATEGORIES.get(code)
