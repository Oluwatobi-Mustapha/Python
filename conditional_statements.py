"""Day 3: Conditional Statements
AWS Service Mapper: Determines appropriate AWS service based on user requirements
"""


def main():
    """Map user requirements to AWS services."""
    service_map = {
        "virtual network": "VPC",
        "database": "RDS",
        "serverless_computing": "Lambda",
        "file storage": "S3",
        "virtual_server": "EC2",
        "security": "IAM",
        "management": "CloudTrail",
    }
    # Get user input and normalize
    user_requirement = input("Enter your requirement: ").lower().strip()

    # Look up service
    aws_service = service_map.get(user_requirement, "unknown")

    # Checking what to print base on user_requirement and input and display result
    if aws_service != "unknown":
        print(f"The AWS service required is {aws_service}.")

    else:
        print(f"Error: '{user_requirement}' is not a valid requirement.")
        print(f"Valid options are: {'| '.join(service_map.keys())}")


if __name__ == "__main__":
    main()
