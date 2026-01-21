import sys
import datetime

# sys.argv[1] will capture the first argument passed from Terraform
user_arn = sys.argv[1]
current_time = datetime.datetime.now()

log_entry = f"ALERT: User created! ARN: {user_arn} | Time: {current_time}\n"

# Open 'audit_log.txt' and append the new entry
with open("audit_log.txt", "a") as f:
    f.write(log_entry)

print(f"Successfully logged: {user_arn}")
