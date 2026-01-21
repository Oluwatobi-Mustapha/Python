def audit_user(user):
    if not user.get("mfa_enabled"):
        return "ALERT: No MFA"
    return "Compliant"


def main():
    iam_users = [
        {"username": "admin_tobi", "mfa_enabled": True},
        {"username": "intern_john", "mfa_enabled": False},
        {"username": "suspicious_bot"},
    ]
    for user in iam_users:
        status = audit_user(user)
        print(f"\nUser {user['username']} status - {status}")


if __name__ == "__main__":
    main()
