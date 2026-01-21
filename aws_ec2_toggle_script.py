"""
AWS EC2 TOGGLE SCRIPT
---------------------
This script acts like a light switch for a specific server:
1. If the server exists -> It terminates (deletes) it.
2. If the server is missing -> It creates a new one.

Useful for testing without accumulating a huge bill!
"""

import boto3
from botocore.exceptions import ClientError

# --- CONFIGURATION ---
# We use Stockholm (eu-north-1) because it's often cheaper, but it requires 't3' instances.
REGION = "eu-north-1"
INSTANCE_NAME = "practical-ec2"
AMI_ID = "ami-05957b13c4a38c156"  # Amazon Linux 2023 in eu-north-1
KEY_PAIR_NAME = "boto3"  # ACTION REQUIRED: Change this to a KeyPair you own!

# 1. Connect to AWS
ec2 = boto3.client("ec2", region_name=REGION)

print(f"Checking status of '{INSTANCE_NAME}'...")

# 2. Check if the server already exists
# We filter by Name TAG and ensure we only look at "alive" servers (ignoring terminated ones)
response = ec2.describe_instances(
    Filters=[
        {"Name": "tag:Name", "Values": [INSTANCE_NAME]},
        {"Name": "instance-state-name", "Values": ["running", "pending", "stopped"]},
    ]
)

# 3. The Toggle Logic
# If the list is not empty, it means the server exists -> So we KILL it.
if response["Reservations"]:
    # Dig through the messy JSON to find the ID of the first server found
    instance_id = response["Reservations"][0]["Instances"][0]["InstanceId"]

    print(f"Found active instance: {instance_id}")
    print("Toggle Mode: Switching OFF (Terminating)...")

    # Terminate the instance using the ID we just found
    ec2.terminate_instances(InstanceIds=[instance_id])

    print("Termination request sent. Goodbye!")
    exit()  # STOP HERE! We don't want to create a new one immediately.

# 4. Creation Logic
# If we reached this point, no server was found -> So we CREATE it.
print("No instance found. Toggle Mode: Switching ON (Creating)...")

try:
    response = ec2.run_instances(
        ImageId=AMI_ID,
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",  # Must be t3 for Stockholm (t2 doesn't exist there)
        KeyName=KEY_PAIR_NAME,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    # IMPORTANT: This tag is how we find the server next time!
                    {"Key": "Name", "Value": INSTANCE_NAME},
                ],
            },
        ],
    )

    # Print the new ID so we know it worked
    new_id = response["Instances"][0]["InstanceId"]
    print(f"Success! Created new instance: {new_id}")

except Exception as e:
    print(f"Failed to create instance: {e}")
