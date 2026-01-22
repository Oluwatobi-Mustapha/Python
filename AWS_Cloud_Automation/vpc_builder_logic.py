import boto3
from botocore.exceptions import ClientError

# --- CONFIGURATION ---
VPC_CIDR_BLOCK = '10.0.0.0/16'
SUBNET_CIDR_BLOCK = '10.0.1.0/24'
SECURITY_GROUP_NAME = 'Boto3-sg'

# 1. Create the vpc 
client = boto3.client('ec2')
vpc_name = 'tobi-vpc'

vpc_waiter = client.get_waiter('vpc_available')

vpc_response = client.create_vpc(CidrBlock=VPC_CIDR_BLOCK )

vpc_id = vpc_response['Vpc']['VpcId']

vpc_waiter.wait(VpcIds=[vpc_id])

print(vpc_id)

# 2. Create the subnet with vpc id
subnet_waiter = client.get_waiter('subnet_available')

subnet_response = client.create_subnet(CidrBlock=SUBNET_CIDR_BLOCK, VpcId=vpc_id)

subnet_id = subnet_response['Subnet']['SubnetId']

subnet_waiter.wait(SubnetIds=[subnet_id])


print(subnet_id)

# 3. Create the internet gateway
ig_name = 'tobi-internet'
igw_response = client.create_internet_gateway()

igw_id = igw_response['InternetGateway']['InternetGatewayId']
print(igw_id)

# 4. Connect the vpc to the Internet
response = client.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

# 5. Create route table
rt_response = client.create_route_table(VpcId = vpc_id)

rt_id = rt_response['RouteTable']['RouteTableId']
print(rt_id)

# 6. Create the route
r_response = client.create_route(RouteTableId=rt_id, DestinationCidrBlock='0.0.0.0/0', GatewayId=igw_id)

# 7. Associate the subnet to the route
art_response = client.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)

# 8. Create Security Group
try:
    sg_response = client.create_security_group(Description='Boto3', GroupName=SECURITY_GROUP_NAME, VpcId=vpc_id)
    sg_id = sg_response['GroupId']
    print(sg_id)

except ClientError as e:  # Handle error from duplicates
    
    if e.response['Error']['Code'] == 'InvalidGroup.Duplicate':
        print("Security Group already exists.")
        
        # Search for the existing group
        response = client.describe_security_groups(
            Filters=[
                {
                    'Name': 'group-name',
                    'Values': [SECURITY_GROUP_NAME]
                },
            ]
        )
        sg_id = response['SecurityGroups'][0]['GroupId']
        print(f"Found existing ID: {sg_id}")

    else:
        raise e

# 9. Authorize Ingress
asi_response = client.authorize_security_group_ingress(
    GroupId=sg_id,
    IpPermissions=[
        {
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [
                {
                    'Description': 'string',
                    'CidrIp': '0.0.0.0/0'
                }
            ]        
        }    
    ]   
)    