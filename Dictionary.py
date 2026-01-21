"""Create a dictionary of AWS services and modify the dictionary appropriately"""


def main():
    # A dictionary of AWS services and their descriptions

    aws_services = {
        "S3": {"description": "Simple storage service", "launch_year": 2006},
        "Lambda": {"description": "Serverless compute", "launch_year": 2014},
        "EC2": {"description": "Elastic compute cloud", "launch_year": 2006},
    }
    print(f"These are simple AWS services and their descriptions:{aws_services}")

    # Modifying the dictionary
    aws_services["Lambda"]["description"] = "AWS serverless compute storage"
    print(f"\nUpdated description of Lambda: {aws_services}")

    # Accessing an item in the dictionary
    lambda_description = aws_services["Lambda"]
    print(f"\nThe description of Lambda is: {lambda_description}")

    # updating a service to the dictionary
    aws_services["VPC"] = {"description": "Virtual Private Cloud", "launch_year": 2009}
    print(f"\nAdded VPC: {aws_services['VPC']}")

    # Removing from dictionary
    aws_services.pop("VPC", None)
    print(f"\nVPC removed: {aws_services}")

    # Displaying different aspects of the dictionary
    print(aws_services.keys())
    print(aws_services.values())
    print(aws_services.items())

    ec2_data = aws_services["EC2"]  # Get the box once

    print(f"Service: EC2")
    print(f"Description: {ec2_data['description']}")  # Grab description
    print(f"Launched: {ec2_data['launch_year']}")  # Grab year

    print(
        f"EC2 Launch Year: {aws_services['EC2']['launch_year']}"
    )  # Grab only launch year from the ec2 details
    print(
        f"EC2 Description: {aws_services['EC2']['description']}"
    )  # Grab only description from the ec2 detail

    """Scenario: You are scanning a user profile. 
    Sometimes the 'mfa_enabled' key is missing entirely (which means they are insecure).
    If you try to access a missing key directly, you crash."""

    user = {"name": "Tobi", "role": "admin"}

    mfa_status = user.get("mfa_enabled", False)
    print(mfa_status)


if __name__ == "__main__":
    main()
