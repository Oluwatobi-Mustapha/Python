import boto3
from botocore.exceptions import ClientError

# Configuration
VPC_CIDR_BLOCK = '10.0.0.0/16'
SUBNET_CIDR_BLOCK = '10.0.1.0/24'
SECURITY_GROUP_NAME = 'Boto3-sg'

client = boto3.client('ec2')

# 1. find and delete security group
try:
    sg_response = client.describe_security_groups(
        Filters=[{'Name': 'group-name', 'Values': [SECURITY_GROUP_NAME]}]
    )
    if sg_response['SecurityGroups']:
        sg_id = sg_response['SecurityGroups'][0]['GroupId']
        client.delete_security_group(GroupId=sg_id)
        print(f"Deleted Security Group: {sg_id}")

except ClientError as e:
    print(f"Error deleting SG: {e}")

# Step 2. Find and Delete subnet
# We need to find the subnet ID using its CIDR block before we can delete it.

subnet_response = client.describe_subnets(
    Filters=[{'Name': 'cidr-block', 'Values': [SUBNET_CIDR_BLOCK]},]
)
if subnet_response['Subnets']:
    # Access the first subnet in the list, then grab its ID
    subnet_id = subnet_response['Subnets'][0]['SubnetId']
    client.delete_subnet(SubnetId=subnet_id)
    print(f"Deleted Subnet: {subnet_id}")


# 3. Find the VPC id to detach igw 

vpc_response = client.describe_vpcs(
    Filters=[{'Name': 'cidr', 'Values':[VPC_CIDR_BLOCK]}]
)
if vpc_response['Vpcs']:
    vpc_id = vpc_response['Vpcs'][0]['VpcId']
    print(vpc_id)

#4. Detach igw 
igw_response = client.describe_internet_gateways(
   Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]},] # Use the ID we just found
)

if igw_response['InternetGateways']:
    igw_id = igw_response['InternetGateways'][0]['InternetGatewayId']
    print(igw_id)

    # Now we have the IGW ID

# My personal Note from doc: Detaches an internet gateway from a VPC, disabling connectivity between the internet and the VPC.
# The VPC must not contain any running instances with Elastic IP addresses or public IPv4 addresses.

# Step A: Detach it
    igwd_response = client.detach_internet_gateway(
        InternetGatewayId=igw_id,
        VpcId=vpc_id
    )
    print(f"Detached IGW: {igw_id} from {vpc_id}")

    # Step B: Delete it
    client.delete_internet_gateway(InternetGatewayId=igw_id)

    print(f"Deleted IGW: {igw_id}")

# 5. CleanUp custom routables associate with my custom vpc
rt_response = client.describe_route_tables(
    Filters=[{'Name':'vpc-id', 'Values': [vpc_id]}]
)

if rt_response['RouteTables']:
    for table in rt_response['RouteTables']:
        # Check if this table is NOT the main one
        is_main = False
        for assoc in table.get('Associations', []):
            if assoc.get('Main'):
                is_main = True
        
        if not is_main:
            custom_rt_id = table['RouteTableId']
            # Now we can delete it
            rt_response = client.delete_route_table( RouteTableId= custom_rt_id)
            print(f"Deleted custom Route Table: {custom_rt_id}")


# Step 6. Deleting the Container(Vpc)
vpc_response = client.delete_vpc(
    VpcId=vpc_id
)
print(f"delete Vpc {vpc_id}")