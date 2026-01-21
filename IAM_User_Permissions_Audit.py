"""A small script to manage IAM users flagged for review."""


def main():
    flagged_users = [
        "admin_john",
        "dev_sarah",
        "readonly_mike",
        "admin_grace",
        "dev_tom",
        "service_account_01",
    ]
    first_user = flagged_users[0]
    print(
        f"The first user in the list and the highest priority to review is {first_user}\n"
    )

    last_user = flagged_users[-1]
    print(f"The last user is {last_user}\n")

    # The security team realized 'readonly_mike' was flagged by mistake. He's at index 2.

    cleared_user = flagged_users.pop(2)
    print(f"The removed username is {cleared_user}\n")

    # A new suspicious user was detected: 'extern_vendor_03'

    flagged_users.append("extern_vendor_03")
    print(
        f"The new suspicious user has been added at the end of this list: {flagged_users}\n"
    )

    # The first user 'admin_john' has been reviewed and is now confirmed malicious.
    if "admin_john" in flagged_users:
        index = flagged_users.index("admin_john")
        flagged_users[index] = "MALICIOUS_admin_john"
        threat_actor = flagged_users[index]
        print(
            f"'admin_john' has now been confirmed to be malicious and he has been renamed {threat_actor} and thereby marked for escalation\n"
        )

    next_batch = flagged_users[1:4]
    print(f"The next batch of users to review are: {next_batch}\n")

    print(
        f"the total number of users still in the flagged list are: {len(flagged_users)}"
    )


if __name__ == "__main__":
    main()
