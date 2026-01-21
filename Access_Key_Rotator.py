"""Scenario: You have a list of AWS Access Keys IDs. You need to rotate them programmatically."""


def main():
    # deletion of the first key
    access_keys = ["AKIA_OLD_1", "AKIA_OLD_2", "AKIA_NEW_1", "AKIA_NEW_2"]
    deleted_keys = access_keys.pop(0)
    print(f"The first key called {deleted_keys} has been deleted\n")

    # adding key

    access_keys.insert(0, "AKIA_URGENT")
    print(
        f"A high-priority key has been added to the beginning of this list: {access_keys}\n"
    )

    # confirming if a key is present

    if "AKIA_OLD_2" in access_keys:
        index = access_keys.index("AKIA_OLD_2")
        print(f"The index number of 'AKIA_OLD_2' is {index}\n")

    # The total output of the access key

    print(f"The final list of key is: {access_keys}\n")


if __name__ == "__main__":
    main()

"""NOTE: I will never push real access key credentials to git, this is for practice sake"""
