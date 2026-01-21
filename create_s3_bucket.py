import boto3
from botocore.exceptions import ClientError

s3_client = boto3.client("s3")

bucket_name = "google"

try:
    s3_client.create_bucket(Bucket=bucket_name)
    print(f"Bucket has been successfully created: {bucket_name}")

except ClientError as e:
    error_code = e.response["Error"]["Code"]

    if error_code == "BucketAlreadyOwnedByYou":
        print(f" Note: This bucket {bucket_name} is already owned by you")

    elif error_code == "BucketAlreadyExists":
        print(f"Unfortunately, bucket:{bucket_name} already exists globally")

    else:
        print(f"Unknown Error {e}")
# import boto3

# s3 = boto3.resource('s3')

# for bucket in s3.buckets.all():
#     print(bucket.name)
