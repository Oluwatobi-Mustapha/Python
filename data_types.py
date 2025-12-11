""" A variable of different data types
"""
DEFAULT_INSTANCE_COUNT = 500
BILLING_PERIOD_HOURS = 50
T4g_LARGE_HOURLY_COST = 0.0672  # constants for important details so that I can easily locate and modify them when needed.

def main():

    """Demonstrate Python data types with AWS instance cost calculation."""

    # string (str)

    instance_type = 't4g.large'
    message = "My instances are of type: "

    # Integer (Int)
    number_of_instances = DEFAULT_INSTANCE_COUNT
    hours_running = BILLING_PERIOD_HOURS

    print(f"\n{message}{instance_type}. I have {number_of_instances} of them and they have been running for {hours_running} hours.")

    # Boolean (bool)
    running_instances = True
    print(f"\nAre all my instances running?\n{running_instances}")
    print(f"\nMy variable is of: {type(running_instances)}")


    # Floating-point number(float)
    instance_cost_per_hour = T4g_LARGE_HOURLY_COST
    print(f"\nThe price of running each of this instance per hour is: ${instance_cost_per_hour}")

    total_cost = number_of_instances * hours_running * instance_cost_per_hour
    print(f"\nTotal cost: ${total_cost:,.2f}") # .2f = 2 decimal places

if __name__ == '__main__': # Entry point
    main()


