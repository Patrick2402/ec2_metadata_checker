import boto3
import sys
from colorama import init, Fore, Style

# Initialize colorama for colored output
init()

def check_metadata_security():
    try:
        # Get region from arguments or use default
        region = sys.argv[1] if len(sys.argv) > 1 else None
        
        # Create EC2 client
        ec2 = boto3.client('ec2', region_name=region)
        
        # Get all instances
        print(f"{Fore.CYAN}Retrieving EC2 instance information...{Style.RESET_ALL}")
        response = ec2.describe_instances()
        
        # Security summary
        instances_count = 0
        vulnerable_count = 0
        
        print("\n" + "=" * 110)
        print(f"{Fore.YELLOW}EC2 INSTANCE METADATA - SECURITY ASSESSMENT{Style.RESET_ALL}")
        print("=" * 110)
        
        # Header format - fixed width for proper alignment
        header = f"{'INSTANCE_ID':<22} {'IMDS VERSION':<15} {'TOKEN STATUS':<15} {'HOP LIMIT':<10} {'ENDPOINT':<10} {'IPV6':<10} {'META TAGS':<10} {'SECURITY':<15}"
        print(header)
        print("-" * 110)
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instances_count += 1
                instance_id = instance['InstanceId']
                
                # Check if instance has metadata information
                if 'MetadataOptions' in instance:
                    metadata = instance['MetadataOptions']
                    
                    # Collect configuration values
                    http_tokens = metadata.get('HttpTokens', 'unknown')
                    http_endpoint = metadata.get('HttpEndpoint', 'unknown')
                    hop_limit = metadata.get('HttpPutResponseHopLimit', 'unknown')
                    ipv6 = metadata.get('HttpProtocolIpv6', 'unknown')
                    tags_access = metadata.get('InstanceMetadataTags', 'unknown')
                    
                    # Determine IMDS version and security assessment
                    imds_version = "IMDSv1" if http_tokens == 'optional' else "IMDSv2"
                    
                    # Security assessment
                    security_issues = []
                    
                    if http_tokens == 'optional':
                        vulnerable_count += 1
                        security_issues.append("IMDSv1 (vulnerable)")
                    
                    if hop_limit and isinstance(hop_limit, int) and hop_limit > 1:
                        security_issues.append("high hop limit")
                    
                    if tags_access == 'enabled':
                        security_issues.append("tags exposed")
                    
                    # Determine overall security rating
                    if not security_issues:
                        security_rating = f"{Fore.GREEN}SECURE{Style.RESET_ALL}"
                    elif "IMDSv1 (vulnerable)" in security_issues:
                        security_rating = f"{Fore.RED}VULNERABLE{Style.RESET_ALL}"
                    else:
                        security_rating = f"{Fore.YELLOW}WARNING{Style.RESET_ALL}"
                    
                    # Color the IMDS version
                    if imds_version == "IMDSv1":
                        imds_version_colored = f"{Fore.RED}{imds_version}{Style.RESET_ALL}"
                    else:
                        imds_version_colored = f"{Fore.GREEN}{imds_version}{Style.RESET_ALL}"
                    
                    # Color the token status
                    if http_tokens == 'required':
                        token_status_colored = f"{Fore.GREEN}{http_tokens}{Style.RESET_ALL}"
                    else:
                        token_status_colored = f"{Fore.RED}{http_tokens}{Style.RESET_ALL}"
                    
                    # Print instance information with fixed widths
                    instance_line = f"{instance_id:<22} {imds_version_colored:<15} {token_status_colored:<15} {hop_limit:<10} {http_endpoint:<10} {ipv6:<10} {tags_access:<10} {security_rating:<15}"
                    print(instance_line)
                else:
                    print(f"{instance_id:<22} {'N/A':<15} {'N/A':<15} {'N/A':<10} {'N/A':<10} {'N/A':<10} {'N/A':<10} {Fore.YELLOW}{'UNKNOWN'}{Style.RESET_ALL}")
        
        # Summary
        print("\n" + "=" * 110)
        print(f"{Fore.CYAN}SUMMARY:{Style.RESET_ALL}")
        print(f"Scanned instances: {instances_count}")
        vulnerable_percent = (vulnerable_count / instances_count) * 100 if instances_count > 0 else 0
        print(f"Vulnerable instances (IMDSv1): {vulnerable_count} ({vulnerable_percent:.1f}%)")
        
        if vulnerable_count > 0:
            print(f"\n{Fore.YELLOW}RECOMMENDATION:{Style.RESET_ALL}")
            print("Update metadata configuration for vulnerable instances by running for each:")
            print(f"aws ec2 modify-instance-metadata-options --instance-id INSTANCE_ID --http-tokens required --http-endpoint enabled")
        
        print("\n" + "=" * 110)
        print(f"{Fore.YELLOW}IMPORTANT METADATA SECURITY CONFIGURATIONS:{Style.RESET_ALL}")
        print(f"- {Fore.GREEN}HttpTokens=required{Style.RESET_ALL}: IMDSv2 requires tokens, protecting against SSRF attacks")
        print(f"- {Fore.GREEN}HttpPutResponseHopLimit=1{Style.RESET_ALL}: Restricts requests to local network only")
        print(f"- {Fore.GREEN}InstanceMetadataTags=disabled{Style.RESET_ALL}: Prevents exposing sensitive information via tags")
        print(f"- {Fore.GREEN}HttpProtocolIpv6=disabled{Style.RESET_ALL}: Disables IPv6 access to metadata when not needed")
        print("=" * 110)
        
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        print("Make sure a region is provided or AWS CLI default region is configured.")
        print("Usage: python script.py [region]")
        sys.exit(1)

if __name__ == "__main__":
    check_metadata_security()