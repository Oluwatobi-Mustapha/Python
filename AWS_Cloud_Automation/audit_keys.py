import boto3

client = boto3.client('iam')

# Step 0. Lists the IAM users
iam_response = client.list_users(
    MaxItems=20  
)
users = iam_response

# Step 1. Iterate over users
for user in users.get('Users', []):
    username = user.get('UserName')

    # Step 2: List access keys
    keys_response = client.list_access_keys(UserName=username)
    print(f"\nKeys for {username}: {keys_response['AccessKeyMetadata']}")

    # Step 3. Look for active keys
    active_count = 0
    for key in keys_response['AccessKeyMetadata']:
        if key['Status'] == 'Active':
            active_count+=1
        # Step 4. Check the total
    if active_count>1:
        print(f"\nuser {username} has {active_count} active_keys")
    