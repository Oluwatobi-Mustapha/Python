def main():
    all_policies = [
        {
            "Name": "Policy_A",
            "Action": "s3:ListBucket",
            "Resource": ["arn:aws:s3:::my-bucket", "*"],
        },
        {"Name": "Policy_B", "Action": "ec2:DescribeInstances"},
        {
            "Name": "Policy_C",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-secure-bucket",
        },
    ]

    for policy in all_policies:
        # Printing the name to know which one I'm looking for
        print(f"\nChecking Policy: {policy.get('Name')}...")

        # sending that single policy to validator function
        validate_resource(policy)


# using existing function to handle the logic for ONE policy at a time.
def validate_resource(policy):
    resource_target = policy.get("Resource")

    if not resource_target:
        print(f"\nAlert: Missing Resource")
    elif "*" in resource_target:
        print(
            f"\nCritical Warning: Resource is set to Wildcard (*). This is overly permissive!"
        )
    else:
        print(f"\nValid specific resource found.")


if __name__ == "__main__":
    main()
