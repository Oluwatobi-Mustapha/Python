"""This script manages Amazon EC2 instances using the Boto3 Python SDK"""

import boto3
from botocore.exceptions import ClientError

# Create ec2 resource and instance name
ec2 = boto3.client("ec2", region_name="eu-north-1")
instance_name = "practical-ec2"

# Store instance ID
instance_id = None

# Check if the instance already exists
# and only work with an instance that hasn't already been terminated

print(f"Checking for existing '{instance_name}'...")

response = ec2.describe_instances(
    Filters=[
        {"Name": "tag:Name", "Values": [instance_name]},
        {"Name": "instance-state-name", "Values": ["running", "pending", "stopped"]},
    ]
)
# In Python, an empty list [] matches as False. A list with items matches as True.
# So we can just say "if response['Reservations']:"
if response["Reservations"]:
    # 1. Get the ID dynamically from the search result we just got
    # We go into the first reservation [0] and the first instance [0]
    instance_id = response["Reservations"][0]["Instances"][0]["InstanceId"]

    print(f"Instance '{instance_name}' with ID {instance_id} already exists.")
    print("Terminating it now...")

    # 2. Using snippet from docs
    # We pass the variable 'instance_id' instead of a hardcoded string like the docs said.
    ec2.terminate_instances(
        InstanceIds=[
            instance_id,
        ],
    )
    print("Termination successful. Exiting.")
    exit()  # Stop the script so we don't try to create a new one
print("No duplicates found. Proceeding to launch...")

# Launch a new EC2 instance if it hasn't already been created
try:
    response = ec2.run_instances(
        ImageId="ami-05957b13c4a38c156",  # Replace with a real AMI from your region
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",  # Changed from t2.micro because t2 isn't in eu-north-1
        KeyName="boto3",
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": instance_name},
                ],
            },
        ],
    )
    print(response["Instances"][0]["InstanceId"])
except Exception as e:
    print(f"Failed to create instance: {e}")
