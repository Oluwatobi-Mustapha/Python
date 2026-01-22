import boto3
from botocore.exceptions import ClientError

# Configuration
VPC_CIDR_BLOCK = '10.0.0.0/16'
SUBNET_CIDR_BLOCK_1 = '10.0.1.0/24'
SUBNET_CIDR_BLOCK_2 = '10.0.2.0/24'
SUBNET_CIDR_BLOCK_3 = '10.0.3.0/24'
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

# Get the first 3 available AZs dynamically

azs_response = client.describe_availability_zones(
    Filters=[{'Name': 'state', 'Values': ['available']}]
)

# Extract the ZoneName
availability_zones = [
    az['ZoneName'] 
    for az in azs_response['AvailabilityZones'][:3]
]
print("Using Availability Zones:", availability_zones)

subnet_1_response = client.create_subnet(CidrBlock=SUBNET_CIDR_BLOCK_1, VpcId=vpc_id, AvailabilityZone=availability_zones[0])
subnet_2_response = client.create_subnet(CidrBlock=SUBNET_CIDR_BLOCK_2, VpcId=vpc_id, AvailabilityZone=availability_zones[1])
subnet_3_response = client.create_subnet(CidrBlock=SUBNET_CIDR_BLOCK_3, VpcId=vpc_id, AvailabilityZone=availability_zones[2])

print(f"subnet_1_ID = '{subnet_1_response['Subnet']['SubnetId']}', subnet_2_ID = '{subnet_2_response['Subnet']['SubnetId']}', subnet__ID = '{subnet_3_response['Subnet']['SubnetId']}' ")

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
print(f"Created default route (0.0.0.0/0) to IGW {igw_id} in route table {rt_id}")

# 7. Associate subnets with the route table and mark them as public

# - Associating the route table ensures traffic to 0.0.0.0/0 is sent through the Internet Gateway.
# - Enabling MapPublicIpOnLaunch is required so EC2 instances launched in these subnets automatically receive public IPs.
# - Without this, instances will be unreachable even though the IGW and routes exist 

public_subnet_responses = [
    subnet_1_response,
    subnet_2_response,
    subnet_3_response
]

for subnet_response in public_subnet_responses:
    subnet_id = subnet_response['Subnet']['SubnetId']

    # Associate subnet with the route table (makes it use the IGW route)
    client.associate_route_table(
        RouteTableId=rt_id,
        SubnetId=subnet_id
    )

    # Ensure instances launched in this subnet receive public IPs
    client.modify_subnet_attribute(
        SubnetId=subnet_id,
        MapPublicIpOnLaunch={'Value': True} # NOTE: Public subnet = IGW route + public IP mapping (both required)
    )

    print(f"Subnet {subnet_id} associated with route table {rt_id} and marked as public") 
    

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