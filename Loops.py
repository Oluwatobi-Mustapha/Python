"""Use a list of aws services and demonstrate various loop operation"""
def main():
    # List of aws services
    aws_services = ['EC2', 'S3', 'RDS', 'VPC', 'IAM']
    print(f"AWS services are: {aws_services}")

    # Use a for loop to iterate through the list
    print(f"\nUsing a for loop to iterate through the list")
    for service in aws_services:
        print(service)

    # Use a while loop to iterate through the list in reverse order
    print(f"\nUsing a while loop to iterate through the list in a reverse order: ")
    index = len(aws_services) -1
    while index >= 0:
        print(aws_services[index])
        index -= 1
    # Pythonic way
    for service in reversed(aws_services):
        print(service)

    # Using enumerate() with a for loop to get both index and values
    print(f"\nUsing enumerate() to get both index and values")
    for index, service in enumerate(aws_services):
        print(f"\nService # {index + 1}: {service}")

if __name__ == '__main__':
    main()