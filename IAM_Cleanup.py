"""You are an IAM Engineer. You have a raw list of usernames scraped from an old AWS account.
You need to clean it up programmatically before migrating them to a new Identity Provider.
"""


def main():
    """Defining the list"""

    iam_users = ["admin", "s_jobs", "b_gates", "j_bezos", "dev_ops", "root"]

    # The user 'root' should never be used for daily tasks. Check if 'root' is in the list.
    if "root" in iam_users:
        iam_users.remove("root")
        print(f"Security Alert: root user removed\n")

    # Adding a new joined engr called 'e_musk'

    iam_users.append("e_musk")
    print(f"New hire added. Current list: {iam_users}\n")

    # Realized there was an imposter called 's_jobs' who is just a contractor, not an employee.
    if "s_jobs" in iam_users:
        index = iam_users.index("s_jobs")
        iam_users[index] = "contractor_01"
        print(f"User 's_jobs' converted to 'contractor_01.\n")

    # Audit: The auditor only want to see the first 3 users for naming conventions
    slice_list = iam_users[0:3]
    print(f"The first 3 users are: {slice_list}\n")

    # Final count: The total number of active users
    print(f"Total active users: {len(iam_users)}")
    # or
    # active_users = len(iam_users)
    # print(f"The total number of active users: {active_users}\n")


if __name__ == "__main__":
    main()
