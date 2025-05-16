import boto3
import sys
import json
import os
from datetime import datetime
from colorama import init, Fore, Style
from rich.console import Console
from rich.table import Table

# Initialize colorama for colored output
init()

# Initialize Rich console
console = Console()

def check_metadata_security(output_txt=None, output_json=None):
    try:
        # Get region from arguments or use default
        region = sys.argv[1] if len(sys.argv) > 1 else None
        
        # Create EC2 client
        ec2 = boto3.client('ec2', region_name=region)
        
        # Get all instances
        console.print(f"Retrieving EC2 instance information...", style="cyan")
        response = ec2.describe_instances()
        
        # Security summary
        instances_count = 0
        vulnerable_count = 0
        sg_protected_count = 0
        
        # Create Rich table
        table = Table(title="EC2 INSTANCE METADATA - SECURITY ASSESSMENT")
        
        # Add columns
        table.add_column("INSTANCE_ID", style="blue")
        table.add_column("IMDS VERSION")
        table.add_column("TOKEN STATUS")
        table.add_column("HOP LIMIT")
        table.add_column("ENDPOINT")
        table.add_column("IPV6")
        table.add_column("META TAGS")
        table.add_column("SG PROTECTED")
        table.add_column("SECURITY")
        table.add_column("REASON", style="yellow")
        
        # Prepare data for JSON export
        json_data = {
            "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "region": region or "default",
            "instances": [],
            "summary": {}
        }
        
        # Prepare data for TXT export
        txt_content = ["EC2 INSTANCE METADATA - SECURITY ASSESSMENT"]
        txt_content.append("=" * 120)
        txt_content.append(f"Report date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        txt_content.append(f"Region: {region or 'default'}")
        txt_content.append("=" * 120)
        txt_content.append("")
        
        # Add header to TXT
        txt_content.append(f"{'INSTANCE_ID':<20} {'IMDS VERSION':<15} {'TOKEN STATUS':<15} {'HOP LIMIT':<10} {'ENDPOINT':<10} {'IPV6':<10} {'META TAGS':<10} {'SG PROTECTED':<15} {'SECURITY':<10} {'REASON':<40}")
        txt_content.append("-" * 160)
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instances_count += 1
                instance_id = instance['InstanceId']
                
                # Get security groups for this instance
                security_groups = instance.get('SecurityGroups', [])
                sg_ids = [sg['GroupId'] for sg in security_groups]
                
                # Check Security Group outbound rules to see if metadata access is blocked
                sg_blocks_metadata = False
                
                if sg_ids:
                    # Get detailed security group information
                    sg_details = []
                    for sg_id in sg_ids:
                        sg_response = ec2.describe_security_groups(GroupIds=[sg_id])
                        if sg_response['SecurityGroups']:
                            sg_details.append(sg_response['SecurityGroups'][0])
                    
                    # Check if any SG blocks outbound HTTP port 80
                    for sg in sg_details:
                        blocks_port_80 = True
                        
                        # Check for specific egress rules
                        for rule in sg.get('IpPermissionsEgress', []):
                            # If default allow all (0.0.0.0/0 for all ports)
                            if rule.get('IpProtocol') == '-1':
                                for ip_range in rule.get('IpRanges', []):
                                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                                        blocks_port_80 = False
                                        break
                            
                            # If specific port 80 allowed
                            from_port = rule.get('FromPort', 0)
                            to_port = rule.get('ToPort', 0)
                            if from_port <= 80 <= to_port:
                                for ip_range in rule.get('IpRanges', []):
                                    # Check for all traffic or specific to metadata IP
                                    if ip_range.get('CidrIp') in ['0.0.0.0/0', '169.254.169.254/32']:
                                        blocks_port_80 = False
                                        break
                        
                        if blocks_port_80:
                            sg_blocks_metadata = True
                            break
                    
                    if sg_blocks_metadata:
                        sg_protected_count += 1
                
                # Instance data for JSON
                instance_data = {
                    "instance_id": instance_id,
                    "security_groups": sg_ids
                }
                
                # Check if instance has metadata information
                if 'MetadataOptions' in instance:
                    metadata = instance['MetadataOptions']
                    
                    # Collect configuration values
                    http_tokens = metadata.get('HttpTokens', 'unknown')
                    http_endpoint = metadata.get('HttpEndpoint', 'unknown')
                    hop_limit = metadata.get('HttpPutResponseHopLimit', 'unknown')
                    ipv6 = metadata.get('HttpProtocolIpv6', 'unknown')
                    tags_access = metadata.get('InstanceMetadataTags', 'unknown')
                    
                    # Add metadata details to instance data
                    instance_data.update({
                        "metadata_options": {
                            "http_tokens": http_tokens,
                            "http_endpoint": http_endpoint,
                            "hop_limit": hop_limit,
                            "ipv6": ipv6,
                            "tags_access": tags_access
                        }
                    })
                    
                    # Determine IMDS version and security assessment
                    imds_version = "IMDSv1" if http_tokens == 'optional' else "IMDSv2"
                    instance_data["imds_version"] = imds_version
                    
                    # Security assessment
                    security_issues = []
                    
                    if http_tokens == 'optional' and not sg_blocks_metadata:
                        vulnerable_count += 1
                        security_issues.append("IMDSv1 (vulnerable)")
                    
                    if hop_limit and isinstance(hop_limit, int) and hop_limit > 1:
                        security_issues.append("high hop limit")
                    
                    if tags_access == 'enabled':
                        security_issues.append("tags exposed")
                    
                    # Determine overall security rating and reason
                    reason = None
                    if sg_blocks_metadata:
                        security_rating = "SG PROTECTED"
                        security_style = "blue"
                        reason = "Protected by Security Group rules"
                    elif not security_issues:
                        security_rating = "SECURE"
                        security_style = "green"
                        reason = "IMDSv2 enabled with secure configuration"
                    elif "IMDSv1 (vulnerable)" in security_issues:
                        security_rating = "VULNERABLE"
                        security_style = "red"
                        reason = "IMDSv1 enabled without SG protection"
                    else:
                        security_rating = "WARNING"
                        security_style = "yellow"
                        
                        # Determine specific warnings
                        warning_reasons = []
                        if hop_limit and isinstance(hop_limit, int) and hop_limit > 1:
                            warning_reasons.append(f"Hop limit ({hop_limit}) > recommended (1)")
                        if tags_access == 'enabled':
                            warning_reasons.append("Metadata tags exposed")
                        
                        reason = ", ".join(warning_reasons) if warning_reasons else "Misconfigured metadata options"
                    
                    # Update instance data with security assessment
                    instance_data.update({
                        "security_rating": security_rating,
                        "reason": reason,
                        "sg_blocks_metadata": sg_blocks_metadata,
                        "security_issues": security_issues
                    })
                    
                    # Set styles based on security
                    imds_style = "red" if imds_version == "IMDSv1" and not sg_blocks_metadata else "green"
                    token_style = "red" if http_tokens == 'optional' and not sg_blocks_metadata else "green"
                    sg_style = "green" if sg_blocks_metadata else "red"
                    
                    # Add row to table
                    table.add_row(
                        instance_id,
                        imds_version, 
                        http_tokens,
                        str(hop_limit),
                        http_endpoint,
                        ipv6,
                        tags_access,
                        "Yes" if sg_blocks_metadata else "No",
                        security_rating,
                        reason,
                        style=None,
                        end_section=False
                    )
                    
                    # Add to TXT content
                    txt_content.append(f"{instance_id:<20} {imds_version:<15} {http_tokens:<15} {str(hop_limit):<10} {http_endpoint:<10} {ipv6:<10} {tags_access:<10} {'Yes' if sg_blocks_metadata else 'No':<15} {security_rating:<10} {reason:<40}")
                    
                else:
                    # No metadata options available
                    sg_protected = "Yes" if sg_blocks_metadata else "No"
                    instance_data.update({
                        "metadata_options": "N/A",
                        "security_rating": "UNKNOWN",
                        "reason": "Unable to retrieve metadata options",
                        "sg_blocks_metadata": sg_blocks_metadata
                    })
                    
                    table.add_row(
                        instance_id,
                        "N/A",
                        "N/A",
                        "N/A",
                        "N/A",
                        "N/A",
                        "N/A",
                        sg_protected,
                        "UNKNOWN",
                        "Unable to retrieve metadata options",
                        style=None,
                        end_section=False
                    )
                    
                    # Add to TXT content
                    txt_content.append(f"{instance_id:<20} {'N/A':<15} {'N/A':<15} {'N/A':<10} {'N/A':<10} {'N/A':<10} {'N/A':<10} {sg_protected:<15} {'UNKNOWN':<10} {'Unable to retrieve metadata options':<40}")
                
                # Add instance data to JSON
                json_data['instances'].append(instance_data)
        
        # Print the table
        console.print(table)
        
        # Summary
        console.print("\n[cyan]SUMMARY:[/cyan]")
        console.print(f"Scanned instances: {instances_count}")
        vulnerable_percent = (vulnerable_count / instances_count) * 100 if instances_count > 0 else 0
        sg_protected_percent = (sg_protected_count / instances_count) * 100 if instances_count > 0 else 0
        console.print(f"Vulnerable instances (IMDSv1, no SG protection): {vulnerable_count} ({vulnerable_percent:.1f}%)")
        console.print(f"Protected by Security Groups: {sg_protected_count} ({sg_protected_percent:.1f}%)")
        
        # Add summary to TXT
        txt_content.append("\n")
        txt_content.append("SUMMARY:")
        txt_content.append("-" * 50)
        txt_content.append(f"Scanned instances: {instances_count}")
        txt_content.append(f"Vulnerable instances (IMDSv1, no SG protection): {vulnerable_count} ({vulnerable_percent:.1f}%)")
        txt_content.append(f"Protected by Security Groups: {sg_protected_count} ({sg_protected_percent:.1f}%)")
        
        # Add summary to JSON
        json_data['summary'] = {
            "scanned_instances": instances_count,
            "vulnerable_instances": vulnerable_count,
            "vulnerable_percentage": round(vulnerable_percent, 1),
            "sg_protected_instances": sg_protected_count,
            "sg_protected_percentage": round(sg_protected_percent, 1)
        }
        
        real_vulnerable = vulnerable_count - sg_protected_count
        if real_vulnerable > 0:
            recommendation = "Update metadata configuration for vulnerable instances by running for each:\naws ec2 modify-instance-metadata-options --instance-id INSTANCE_ID --http-tokens required --http-endpoint enabled\n\nAlternatively, you can secure instances by blocking outbound traffic to 169.254.169.254 on port 80 in the Security Group."
            console.print("\n[yellow]RECOMMENDATION:[/yellow]")
            console.print(recommendation)
            
            # Add recommendation to TXT
            txt_content.append("\nRECOMMENDATION:")
            txt_content.append("-" * 50)
            txt_content.append(recommendation)
            
            # Add recommendation to JSON
            json_data['recommendation'] = recommendation
        
        important_configs = [
            "HttpTokens=required: IMDSv2 requires tokens, protecting against SSRF attacks",
            "HttpPutResponseHopLimit=1: Restricts requests to local network only",
            "InstanceMetadataTags=disabled: Prevents exposing sensitive information via tags",
            "HttpProtocolIpv6=disabled: Disables IPv6 access to metadata when not needed",
            "SG Protected: Security Group blocks outbound access to metadata service (port 80)"
        ]
        
        console.print("\n[yellow]IMPORTANT METADATA SECURITY CONFIGURATIONS:[/yellow]")
        for config in important_configs:
            console.print(f"- [green]{config}[/green]")
        
        # Add important configs to TXT
        txt_content.append("\nIMPORTANT METADATA SECURITY CONFIGURATIONS:")
        txt_content.append("-" * 50)
        for config in important_configs:
            txt_content.append(f"- {config}")
        
        # Add important configs to JSON
        json_data['important_configurations'] = important_configs
        
        # Explain SG analysis
        sg_explanation = [
            "This script checks if Security Groups effectively block access to the EC2 metadata service.",
            "It analyzes outbound rules to determine if HTTP traffic (port 80) to 169.254.169.254",
            "is blocked, which would prevent the instance from accessing its metadata.",
            "",
            "Even if an instance uses IMDSv1, it could still be protected if:",
            "1. There are no outbound rules allowing all traffic (0.0.0.0/0)",
            "2. There are no specific rules allowing port 80 traffic to 169.254.169.254",
            "",
            "However, Security Group protection is considered a secondary defense.",
            "AWS best practice is to configure IMDSv2 with required tokens,",
            "as this provides protection directly at the metadata service level."
        ]
        
        console.print("\n[cyan]ABOUT SECURITY GROUP ANALYSIS[/cyan]")
        console.print("=" * 80)
        for line in sg_explanation:
            console.print(line)
        console.print("=" * 80)
        
        # Add SG explanation to TXT
        txt_content.append("\nABOUT SECURITY GROUP ANALYSIS")
        txt_content.append("=" * 80)
        for line in sg_explanation:
            txt_content.append(line)
        txt_content.append("=" * 80)
        
        # Add SG explanation to JSON
        json_data['sg_explanation'] = sg_explanation
        
        # Write to JSON file if specified
        if output_json:
            with open(output_json, 'w') as f:
                json.dump(json_data, f, indent=2, default=str)
            console.print(f"\n[green]JSON report saved to: {output_json}[/green]")
        
        # Write to TXT file if specified
        if output_txt:
            with open(output_txt, 'w') as f:
                f.write('\n'.join(txt_content))
            console.print(f"[green]TXT report saved to: {output_txt}[/green]")
        
    except Exception as e:
        console.print(f"Error: {str(e)}", style="red")
        console.print("Make sure a region is provided or AWS CLI default region is configured.")
        console.print("Usage: python script.py [region] [--txt output.txt] [--json output.json]")
        sys.exit(1)

def explain_sg_analysis():
    sg_explanation = [
        "This script checks if Security Groups effectively block access to the EC2 metadata service.",
        "It analyzes outbound rules to determine if HTTP traffic (port 80) to 169.254.169.254",
        "is blocked, which would prevent the instance from accessing its metadata.",
        "",
        "Even if an instance uses IMDSv1, it could still be protected if:",
        "1. There are no outbound rules allowing all traffic (0.0.0.0/0)",
        "2. There are no specific rules allowing port 80 traffic to 169.254.169.254",
        "",
        "However, Security Group protection is considered a secondary defense.",
        "AWS best practice is to configure IMDSv2 with required tokens,",
        "as this provides protection directly at the metadata service level."
    ]
    
    console.print("\n[cyan]ABOUT SECURITY GROUP ANALYSIS[/cyan]")
    console.print("=" * 80)
    for line in sg_explanation:
        console.print(line)
    console.print("=" * 80)

if __name__ == "__main__":
    # Parse command line arguments
    region = None
    output_txt = None
    output_json = None
    
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "--txt" and i+1 < len(sys.argv):
            output_txt = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == "--json" and i+1 < len(sys.argv):
            output_json = sys.argv[i+1]
            i += 2
        else:
            # Assume it's the region if not a known flag
            if not sys.argv[i].startswith("--"):
                region = sys.argv[i]
            i += 1
    
    # Generate default output filenames if not specified
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    if output_txt is None:
        output_txt = f"ec2_metadata_security_{timestamp}.txt"
    if output_json is None:
        output_json = f"ec2_metadata_security_{timestamp}.json"
    
    # Run the security check
    check_metadata_security(output_txt, output_json)