# EC2 Metadata Security Analyzer

A lightweight tool to assess EC2 instance metadata service (IMDS) configurations and identify potential security vulnerabilities.

## Installation

```
pip install boto3 colorama
```

## Usage

```
python checker.py [region]
```

## Example Output

```
Retrieving EC2 instance information...

=========================================================================
EC2 INSTANCE METADATA - SECURITY ASSESSMENT
=========================================================================
INSTANCE_ID           IMDS VERSION   TOKEN STATUS   HOP LIMIT  SECURITY       
-------------------------------------------------------------------------
i-0123456789ab12312   IMDSv1         optional       1          VULNERABLE     
i-0abcdef012341231r   IMDSv1         optional       1          VULNERABLE     
i-0fedcba9873223222   IMDSv2         required       1          SECURE        

=========================================================================
SUMMARY:
Scanned instances: 3
Vulnerable instances (IMDSv1): 2 (66.7%)

RECOMMENDATION:
aws ec2 modify-instance-metadata-options --instance-id INSTANCE_ID \
  --http-tokens required --http-endpoint enabled
```

## Key Security Checks

- **IMDSv2 Requirement**: Prevents SSRF attacks
- **Hop Limit**: Restricts metadata access to local network
- **Metadata Tags**: Prevents exposure of sensitive tags

## Remediation

Convert vulnerable instances to secure IMDSv2 with:

```
aws ec2 modify-instance-metadata-options \
  --instance-id i-example \
  --http-tokens required
```