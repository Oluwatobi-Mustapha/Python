import boto3
from tabulate import tabulate
from colorama import Fore, Style, init
from botocore.exceptions import ClientError

init(autoreset=True)
client = boto3.client('iam')

# [safety] Get the Identity running this script
current_session = boto3.Session()
current_creds = current_session.get_credentials()
current_key_id = current_creds.access_key if current_creds else None

table_data = []
headers = ["User", "Key ID", "Status", "Created Date", "Action Taken"]

print(f"{Fore.CYAN} Lifecycle Manager: Auto-Deactivate & Auto-Delete...{Style.RESET_ALL}\n")

users = client.list_users(MaxItems=50)

for user in users.get('Users', []):
    username = user.get('UserName')
    keys_response = client.list_access_keys(UserName=username)
    keys_list = keys_response['AccessKeyMetadata']

    if len(keys_list) > 1:
        # Sort: Oldest [0] is the target
        keys_list.sort(key=lambda k: k['CreateDate'])
        key_to_process = keys_list[0]

        # [SAFETY] Self-Preservation Check
        if key_to_process['AccessKeyId'] == current_key_id:
             table_data.append([username, key_to_process['AccessKeyId'], "Active", "N/A", f"{Fore.MAGENTA}SKIPPED (Self){Style.RESET_ALL}"])
             # Skip to the next user, do not deactivate myself!
             continue 
        
        # ---Lifeycle Logic ---
        
        # STAGE 1: Deactivate if Active
        if key_to_process['Status'] == 'Active':
            try:
                client.update_access_key(
                 UserName=username,
                    AccessKeyId=key_to_process['AccessKeyId'],
                    Status='Inactive'
                )
                # Update local status for table
                key_to_process['Status'] = 'Inactive'
                # UI improvement: Tell  customer how much time to wait explicitly
                action_message = f"{Fore.YELLOW}⬇ DEACTIVATED (Waiting 5s recommended and run the script again){Style.RESET_ALL}"
                row_color = Fore.YELLOW

            except ClientError as e:
                # In case AWS complains, catch it 
                action_message = f"{Fore.MAGENTA}AWS ERROR: {e.response['Error']['Code']}{Style.RESET_ALL}"
                row_color = Fore.MAGENTA
           
            

        # STAGE 2: Delete if already inactive
        elif key_to_process['Status'] == 'Inactive':
            try:
                client.delete_access_key(
                 UserName=username,
                    AccessKeyId=key_to_process['AccessKeyId']
              )
                action_message = f"{Fore.RED}DELETED PERMANENTLY{Style.RESET_ALL}"
                row_color = Fore.RED
            except ClientError as e:
                # catch the error
                if e.response['Error']['Code'] == 'InvalidClientTokenId':
                    action_message = f"{Fore.MAGENTA}SYNCING... (Try again in 5s){Style.RESET_ALL}"
                else:
                    action_message = f"{Fore.RED}ERROR: {e.response['Error']['Code']}{Style.RESET_ALL}"
                row_color = Fore.RED

        # --- Reporting ---
        for key in keys_list:
            key_id = key['AccessKeyId']
            date = key['CreateDate'].strftime("%Y-%m-%d")
            
            # Formatting the Target Row
            if key['AccessKeyId'] == key_to_process['AccessKeyId']:
                status = "Inactive" if row_color == Fore.RED else key['Status'] # Show logic
                status_colored = f"{row_color}{status}{Style.RESET_ALL}"
                row_action = action_message
            else:
                # The New Key (Keep)
                status_colored = f"{Fore.GREEN}{key['Status']}{Style.RESET_ALL}"
                row_action = f"{Fore.GREEN}KEEP (Newest){Style.RESET_ALL}"
            
            table_data.append([username, key_id, status_colored, date, row_action])

if table_data:
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
    print(f"\n{Fore.GREEN}✅ Cycle Complete.{Style.RESET_ALL}")
else:
    print(f"\n{Fore.GREEN}✅ COMPLIANT: No duplicate keys found.{Style.RESET_ALL}")