"""
Day 2: Python Operators
Shopping cart discount and free shipping logic.
Demonstrates: Assignment, Arithmetic, Comparison, Logical, Membership operators
"""

# Configuration(constants)
DISCOUNT_RATE = 0.20  # 20% discount
ELIGIBLE_ITEMS = ["orange", "banana", "watermelon"]
FREE_SHIPPING_MIN_QTY = 3  # Minimum quantity for free shipping


def main():
    """Assignment operators"""
    # set variables
    item_name = "banana"
    qty = 6
    item_price = 5  # USD

    """ Arithmetic operators """
    # calculate subtotal
    subtotal = qty * item_price
    print(f"\nitem_name = {item_name} \nsubtotal = ${subtotal}")

    """ Membership operators """
    discount = 0
    if item_name in ELIGIBLE_ITEMS:
        discount = subtotal * DISCOUNT_RATE
    print(f"discount: ${discount:,.2f}")

    """ Comparison operators """
    # check if discount is applied
    was_discount_applied = discount > 0
    print(f"was discount applied?: {was_discount_applied}")

    """ logical operators """
    # check for free-shipping eligibility
    eligibility_for_free_shipping = (
        qty >= FREE_SHIPPING_MIN_QTY and item_name == "banana"
    )
    print(f"Is it eligible for free shipping?: {eligibility_for_free_shipping}")


if __name__ == "__main__":
    main()
