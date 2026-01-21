# Import the boto3 library and os module for file handling
import boto3
from botocore.exceptions import ClientError
import os

# Instantiate a boto3 resource for S3
s3 = boto3.resource("s3")

bucket_name = "my-crud-py-bucket"
try:
    s3.create_bucket(Bucket=bucket_name)
    print(f"Congrats! Your bucket has been successfully created: {bucket_name}")

except ClientError as e:
    error_code = e.response["Error"]["Code"]
    if error_code == "BucketAlreadyOwnedByYou":
        print(f"Note: This bucket is already owned by you {bucket_name}")
    elif error_code == "BucketAlreadyExists":
        print(f"Unfortunately, the bucket '{bucket_name}' already exists globally")
    else:
        print(f"Unknown Error {e}")

# Files to upload
file_1 = "file_1.txt"
file_2 = "file_2.txt"

# Upload file_1 safely (check if it exists locally first)
if os.path.exists(file_1):
    s3.Bucket(bucket_name).upload_file(Filename=file_1, Key=file_1)
else:
    print("file_1.txt does not exist")

# Read and print file_1 from the bucket
obj = s3.Object(bucket_name, file_1)
body = obj.get()["Body"].read()
print(body)

# Replace file_1 contents with file_2 safely
if os.path.exists(file_2):
    with open(file_2, "rb") as f:
        s3.Object(bucket_name, file_1).put(Body=f)
else:
    print("file_2.txt does not exist")

# Delete file_1 from the bucket
s3.Object(bucket_name, file_1).delete()

# Delete the bucket safely (must be emptied first)
bucket = s3.Bucket(bucket_name)
bucket.objects.all().delete()
bucket.delete()
