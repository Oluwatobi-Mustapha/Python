# Python-programming-for-Cloud
Daily Cloud programming in python

# Variables and Data Types

Learned: [str, int, bool, float]

Applied: AWS cost calculation

File: [`data types`](https://github.com/Oluwatobi-Mustapha/Python/blob/main/AWS_Cloud_Automation/data_types.py)

# Python Operators

Learned: [Assignment, Membership, Logical, Comparison, Arithmetic]

Applied: Shopping cart logic

File: [`Operators`](https://github.com/Oluwatobi-Mustapha/Python/blob/main/AWS_Cloud_Automation/operators.py)

# Conditional statement

Learned: [ If, elif, else conditional logic, dictionary, String .join() to combine items with separator, Input validation (.lower(), .strip()) ]

Application: AWS service mapper

File: [`Condtional statements`](https://github.com/Oluwatobi-Mustapha/Python/blob/main/AWS_Cloud_Automation/conditional_statements.py)

# lists.

Learned Python lists by building a basic IAM cleanup script. I now understand lists (mutable) vs tuples (immutable), conditional use of if and in, indexing, and replacing values. I also learned list slicing and its usefulness during audits.

An empty list [] evaluates to False; errors only occur when accessing invalid indexes. pop() removes the last item, while pop(0) removes the first. I used .index() to convert a name to an index so I could modify the list (used in line 20 of the code).

File: [`IAM Cleanup`](https://github.com/Oluwatobi-Mustapha/Python/blob/main/AWS_Cloud_Automation/IAM_Cleanup.py)

# Lists continuation

File:[`Access key rotator`](https://github.com/Oluwatobi-Mustapha/Python/blob/main/AWS_Cloud_Automation/Access_Key_Rotator.py) [`IAM user permission audits`](https://github.com/Oluwatobi-Mustapha/Python/blob/main/AWS_Cloud_Automation/IAM_User_Permissions_Audit.py)

# Dictionaries

Learned how to extracts, modify and assign a new file to a dictionary

File: [`Dict`](https://github.com/Oluwatobi-Mustapha/Python/blob/main/Python_Fundamentals/Dictionary.py)

# Loops

Learned: for, while, else, .get(), in, else, if, break(stop), continue(skip).

Application: Audit tool

File:[`IAM User Audit Tool`](https://github.com/Oluwatobi-Mustapha/Python/blob/main/IAM_User_Audit_Tool.py) [`Loops.py`](https://github.com/Oluwatobi-Mustapha/Python/blob/main/Loops.py)
     
# Functions
Application:[`Functions`](https://github.com/Oluwatobi-Mustapha/Python/blob/main/Python_Fundamentals/Functions.py)

# Exception Handling

Application: [`KeyError`](https://github.com/Oluwatobi-Mustapha/Python/blob/main/Python_Fundamentals/exception_handling.py) [`single policy validator`](https://github.com/Oluwatobi-Mustapha/Python/blob/main/Python_Fundamentals/iam_policy_validator_script.py) [`bulk policy validator`](https://github.com/Oluwatobi-Mustapha/Python/blob/main/Python_Fundamentals/bulk_policy_scanner.py)

Architecture Diagram:<img width="770" height="617" alt="Exception handling excalidraw" src="https://github.com/user-attachments/assets/ce169b30-0ab4-44ad-8f06-595a25d448c0" />

# Boto3

Application: [`S3-Bucket-creation`](https://github.com/Oluwatobi-Mustapha/Python-and-Boto3/blob/main/AWS_Cloud_Automation/s3_bucket_creation.py)

# Boto3 continuation + CRUD
Application: [`S3-crud`](https://github.com/Oluwatobi-Mustapha/Python-and-Boto3/blob/main/AWS_Cloud_Automation/s3_crud.py)

# Boto3 for EC2 mgt
Application: [`EC2-Creation-and-termination`](https://github.com/Oluwatobi-Mustapha/Python-and-Boto3/blob/main/AWS_Cloud_Automation/aws_ec2_toggle.py)

# Boto3 for VPC mgt
* Learned Boto3 Waiters (eventual consistency), Error Handling, Idempotency, Variable Management.
  
Application: [`Automated VPC Setup`](https://github.com/Oluwatobi-Mustapha/Python-and-Boto3/blob/main/AWS_Cloud_Automation/vpc_builder_logic.py) [`Automated VPC Teardown`](https://github.com/Oluwatobi-Mustapha/Python-and-Boto3/blob/main/AWS_Cloud_Automation/vpc_destroyer_logic.py)
           
**Old Script:**
![E2061654-E091-46AE-BE09-1C1874E92B77_4_5005_c](https://github.com/user-attachments/assets/2a82e8bb-1c4d-4627-8cea-0b6b8625771b)

**Updated Script:** <img width="1324" height="368" alt="Screenshot 2026-01-22 at 6 43 29 PM" src="https://github.com/user-attachments/assets/e773a431-0652-40bb-89ca-920f91542c8b" />

<img width="1302" height="257" alt="Screenshot 2026-01-22 at 7 20 25 PM" src="https://github.com/user-attachments/assets/467a69a1-4601-42da-92d3-2c109b9e3390" />

# CIS AWS BENCHMARK
Application:[`audit_keys`](https://github.com/Oluwatobi-Mustapha/Python-and-Boto3/blob/main/AWS_Cloud_Automation/audit_keys.py)

**Discovery of duplicate access keys:**
<img width="2528" height="443" alt="image" src="https://github.com/user-attachments/assets/621f0299-82b7-4393-bc83-d39d18f8f3da" />

 **Deactivation:**
![8EEAE073-E73D-4FA0-ADCF-BAB521A79AEA_1_201_a](https://github.com/user-attachments/assets/78917a78-8176-482c-8e30-9f137bc54edf)

 **AWS Console:**
<img width="2687" height="1497" alt="image" src="https://github.com/user-attachments/assets/e5552f6f-5d9f-41b6-acc4-9858f93325b5" />
 ### Security Notes: All keys displayed are deleted after project, so don't bother hacking me.




