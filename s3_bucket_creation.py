import boto3
from botocore.exceptions import ClientError  # This is for Error handling

s3 = boto3.resource("s3")

bucket_name = "google"

try:
    s3.create_bucket(Bucket=bucket_name)  # For creating the bucket

    print(f"Congrats! Your bucket has been successfully created: {bucket_name}")

except ClientError as e:
    error_code = e.response["Error"][
        "Code"
    ]  # Helps identify what kind of error occurred.

    if error_code == "BucketAlreadyOwnedByYou":
        print(f"Note: This bucket is already owned by you {bucket_name}")

    elif error_code == "BucketAlreadyExists":
        print(f"Unfortunately, The bucket '{bucket_name}' already exists globally")

    else:
        print(f"Unknown Error {e}")
