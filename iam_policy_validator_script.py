"""
Scenario:
You are writing a security tool. This tool reads an IAM policy to see if it is safe.
"""


def main():
    # 1. Defining the policy
    iam_policy = {
        "Version": "2012-10-17",
        "Statement": "Allow",
        "Sid": "PolicyValidation",
        "Effect": "Allow",
        "Action": "s3:ListBucket",
        "Resource": ["arn:aws:s3:::my-bucket", "*"],
    }

    validate_resource(iam_policy)


def validate_resource(policy):
    # 2. Using .get()
    # Attempt to retrieve 'Resource'. If missing, this variable becomes None.
    resource_target = policy.get("Resource")

    # 3. Checking the result

    if not resource_target:
        print("Alert: Missing Resource")
    elif "*" in resource_target:
        print(
            f"Critical Warning: Resource is set to Wildcard (*). This is overly permissive!"
        )
    else:
        print("Valid specific resource found.")


if __name__ == "__main__":
    main()
