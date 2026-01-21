def main():
    # AWS IAM users and their details
    # iam_users = {
    #     'john': {'role': 'admin', 'mfa_enabled': True},
    #     'sarah': {'role': 'developer', 'mfa_enabled': False},
    #     'mike': {'role': 'readonly', 'mfa_enabled': False}
    # }
    #
    # for user in iam_users:
    #     print(user)
    # for users, details in iam_users.items():
    #     print(users, details)
    #
    # for users, details in iam_users.items():
    #     print(details['role'])
    #
    # for username, details in iam_users.items():
    #     print(f"{username}: {details['role']}")

    # for username, details in iam_users.items():
    #     if not details['mfa_enabled']:
    #         print(f"ALERT: {username} has no MFA")
    #
    # users = [
    #     {'name': 'john', 'role': 'admin'},
    #     {'name': 'sarah', 'role': 'developer'},
    #     {'name': 'mike', 'role': 'admin'}
    # ]
    # admin_count = 0
    #
    # for user in users:
    #     if user['role'] == 'admin':
    #         admin_count += 1
    #
    # print(f"Total admins: {admin_count}")
    #
    #  Breaking Out Early
    # Sometimes you don't need to check everything — you just need to find one match:
    # users = ['root', 'sarah', 'john', 'mike']
    #
    # for user in users:
    #     if user == 'root':
    #         print(f"CRITICAL: root user found!")
    #         break
    # else:
    #     print("No root user found") # should be attached to for, not if.

    # # Skipping items
    # users = ['root', 'service_account', 'john', 'mike']
    # for user in users:
    #     if user.startswith('service_'):
    #         continue
    #     print(f"Reviewing: {user}")
    #
    #
    iam_users = {
        "john": {"role": "admin", "mfa_enabled": True},
        "sarah": {"role": "developer", "mfa_enabled": False},
        "mike": {"role": "admin", "mfa_enabled": False},
    }
    for user, details in iam_users.items():
        role = details.get("role", "unknown")
        mfa = details.get("mfa_enabled", False)

        if role == "admin" and not mfa:
            print(f"ALERT: {user} is an admin without MFA")
    # for user, details in iam_users.items():
    #     if details['role']== 'admin' and not details['mfa_enabled']:
    #         print(f"ALERT: {user} is an admin without MFA")


if __name__ == "__main__":
    main()
