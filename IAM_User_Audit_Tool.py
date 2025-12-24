def main():
    iam_users = {
        'admin_john': {'role': 'admin', 'mfa_enabled': True, 'last_login_days': 5},
        'dev_sarah': {'role': 'developer', 'mfa_enabled': False, 'last_login_days': 45},
        'admin_mike': {'role': 'admin', 'mfa_enabled': False, 'last_login_days': 2},
        'readonly_tom': {'role': 'readonly', 'mfa_enabled': True, 'last_login_days': 120},
        'service_backup': {'role': 'service', 'mfa_enabled': False, 'last_login_days': 0},
        'dev_jane': {'role': 'developer', 'mfa_enabled': True, 'last_login_days': 10},
        'admin_root': {'role': 'admin', 'mfa_enabled': False, 'last_login_days': 300}
    }
    count = 0
    for username, details in iam_users.items():
        # Root user detection
        if 'root' in username:
            print(f"CRITICAL: Root user detected - {username}")
            break

        # Service account check
        if username.startswith('service_'):
            continue # meaning to be skipped

        # Admin with no MFA checked
        role = details.get('role', 'unknown')
        mfa  = details.get('mfa_enabled', False)
        if role == 'admin' and not mfa:
            print(f"ALERT: admin user with no MFA detected - {username} ")

        # Checking for stale account
        logins = details.get('last_login_days', 0)
        if logins >= 90:
            count += 1
    else:
        print("Audit complete. No root users found.")

    print(f"Stale accounts: {count}")
if __name__ == '__main__':
    main()