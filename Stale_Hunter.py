def main():
    # days_inactive = [12, 180, 45, 90, 365, 2]
    # revoked_count = 0
    # for number in days_inactive:
    #     if number > 90:
    #         revoked_count +=1
    #         print(f"User inactive for {[number]} days. REVOKE ACCESS")
    #     else:
    #         print(f"User active ({number} days). Safe")
    #     print(f"total number of users access revoked: {revoked_count}")

    users_inactive = {"john": 12, "sarah": 180, "mike": 45, "tom": 90}
    revoked_count = 0
    for user, days in users_inactive.items():
        if days >= 90:
            revoked_count += 1
            print(f"{user} inactive for {days} days. Revoke Access")
        else:
            print(f"{user} has been active for {days} days")
    print(f"\nTotal users revoked: {revoked_count}")


if __name__ == "__main__":
    main()
