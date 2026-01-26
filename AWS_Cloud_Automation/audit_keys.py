import boto3
from tabulate import tabulate
from colorama import Fore, Style, init

# initialize Colorama (autoreset=True means color turns off automatically after print)
init(autoreset=True)

# store all findings here to print one big table at the end
table_data = []



client = boto3.client('iam')

# headers for table
headers = ["User", "Key ID", "Status", "Created Date", "Action Required"]

print(f"{Fore.CYAN} Starting CIS Benchmark Audit: Duplicate Access Keys...{Style.RESET_ALL}\n")

# --- the scan logic ---
# list the iam keys
users = client.list_users(MaxItems=50)

# 1. iterate over users
for user in users.get('Users', []):
    username = user.get('UserName')

    # get the keys
    keys_response = client.list_access_keys(UserName=username)
    keys_list = keys_response['AccessKeyMetadata']

    # only if they have duplicates (more than 1 key)
    if len(keys_list) > 1:

        # sort them: Oldest first [0], Newest last [-1]
        keys_list.sort(key=lambda k: k['CreateDate'])

        # loop through the keys to format them for the table
        for key in keys_list:
            key_id = key['AccessKeyId']
            status = key['Status']
            date = key['CreateDate'].strftime("%Y-%m-%d") # Clean format

            # COLOR LOGIC: Make "Active" keys RED if there are duplicates
            if status == 'Active':
                status_colored = f"{Fore.RED}{status}{Style.RESET_ALL}"
            else:
                status_colored = f"{Fore.GREEN}{status}{Style.RESET_ALL}"

            # DECISION LOGIC: Mark the OLD one for deletion
            if key == keys_list[0]: # The oldest one
                action = f"{Fore.RED}DELETE (Oldest){Style.RESET_ALL}"
            else:
                action = f"{Fore.GREEN}KEEP (Newest){Style.RESET_ALL}"

            # Add row to our table data
            table_data.append([username, key_id, status_colored, date, action])

# --- THE REPORT ---
if table_data:
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
    print(f"\n{Fore.RED}🚨 RISK DETECTED: Found {len(table_data)} keys involved in duplication.{Style.RESET_ALL}")
else:
    print(f"\n{Fore.GREEN}✅ COMPLIANT: No duplicate keys found.{Style.RESET_ALL}")

   