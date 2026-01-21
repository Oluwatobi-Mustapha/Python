"""This script manages Amazon EC2 instances using the Boto3 Python SDK"""

import boto3
from botocore.exceptions import ClientError

# Connection setup
ec2 = boto3.client("ec2", region_name="eu-north-1")
instance_name = "practical-ec2"

# Check if the server exist
# Interested only in running/stopped instances, not terminated ones
print(f"Checking for existing '{instance_name}'...")

response = ec2.describe_instances(
    Filters=[
        {"Name": "tag:Name", "Values": [instance_name]},
        {"Name": "instance-state-name", "Values": ["running", "pending", "stopped"]},
    ]
)

# TOGGLE LOGIC: If found, delete it. If not, create it.
if response["Reservations"]:
    # Get the ID of the instance we just found
    instance_id = response["Reservations"][0]["Instances"][0]["InstanceId"]

    print(f"Instance already exists ({instance_id}). Terminating it...")

    ec2.terminate_instances(InstanceIds=[instance_id])

    print("Termination successful. Exiting.")
    exit()

# CREATE: If we get here, it means no instance was found
print("No duplicates found. Creating new instance...")

try:
    response = ec2.run_instances(
        ImageId="ami-05957b13c4a38c156",  # Amazon Linux 2023 (Stockholm)
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",  # t2.micro is not available in eu-north-1
        KeyName="boto3",  # If you are cloning this, pls change this to a KeyPair you own
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": instance_name}],
            },
        ],
    )
    # Print the new ID so we know it worked
    new_id = response["Instances"][0]["InstanceId"]
    print(f"Success! Created instance: {new_id}")

except Exception as e:
    print(f"Failed to create instance: {e}")
