# EC2 Metadata Security Analyzer

## Overview

EC2 Metadata Security Analyzer is a powerful tool designed to identify security vulnerabilities related to EC2 Instance Metadata Service (IMDS) configurations. It helps you identify instances that are vulnerable to Server-Side Request Forgery (SSRF) attacks that could lead to unauthorized access to AWS credentials.

## Features

- Comprehensive security assessment of all EC2 instances in a region
- Detection of instances using vulnerable IMDSv1 configurations
- Analysis of Security Group rules to identify whether metadata access is effectively blocked
- Detailed reporting with specific reasons for vulnerability findings
- Export capabilities to both TXT and JSON formats for integration with other tools
- Color-coded terminal output for quick visual analysis

## Installation

### Prerequisites

- Python 3.6+
- AWS CLI configured with appropriate permissions
- Required Python packages:
  ```
  pip install boto3 colorama rich
  ```

### AWS Permissions

The tool requires the following AWS permissions:
- `ec2:DescribeInstances`
- `ec2:DescribeSecurityGroups`

## Usage

Basic usage:
```bash
python checker.py [region]
```

Extended options:
```bash
python checker.py [region] --txt output.txt --json output.json
```

Example:
```bash
python checker.py eu-central-1
```

## Understanding Results

The tool categorizes instances into the following security states:

- **SECURE**: Instance is using IMDSv2 with proper configuration
- **VULNERABLE**: Instance is using IMDSv1 and has Security Group rules that allow metadata access
- **SG PROTECTED**: Instance is using IMDSv1 but is protected by Security Group rules
- **WARNING**: Instance has some security configuration issues (e.g., high hop limit)

For each instance, the tool provides a detailed reason for its security assessment, helping you to quickly identify and address specific security issues.

## Example Output

```
Retrieving EC2 instance information...

┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ INSTANCE_ID      ┃ IMDS VERSION  ┃ TOKEN STATUS  ┃ HOP LIMIT┃ ENDPOINT ┃ IPV6     ┃ META TAGS┃ SG PROTECTED  ┃ SECURITY  ┃ REASON                               ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ i-2b61c12323811  │ IMDSv2        │ required      │ 2        │ enabled  │ disabled │ disabled │ No            │ WARNING   │ Hop limit (2) > recommended (1)     │
│ i-2123412312ab   │ IMDSv1        │ optional      │ 1        │ enabled  │ disabled │ disabled │ No            │ VULNERABLE│ IMDSv1 enabled without SG protection│
│ i-1abc122231456  │ IMDSv1        │ optional      │ 1        │ enabled  │ disabled │ enabled  │ Yes           │ SG PROTECT│ Protected by Security Group rules   │
│ i-1d22222abc789  │ IMDSv2        │ required      │ 1        │ enabled  │ disabled │ disabled │ No            │ SECURE    │ IMDSv2 enabled with secure configuration│
└──────────────────┴───────────────┴───────────────┴──────────┴──────────┴──────────┴──────────┴───────────────┴───────────┴──────────────────────────────────────────┘

SUMMARY:
Scanned instances: 4
Vulnerable instances (IMDSv1, no SG protection): 1 (25.0%)
Protected by Security Groups: 1 (25.0%)

RECOMMENDATION:
Update metadata configuration for vulnerable instances by running for each:
aws ec2 modify-instance-metadata-options --instance-id INSTANCE_ID --http-tokens required --http-endpoint enabled

Alternatively, you can secure instances by blocking outbound traffic to 169.254.169.254 on port 80 in the Security Group.
```

## Security Background

### IMDS Versions

- **IMDSv1** - The original metadata service that does not require authentication to access
- **IMDSv2** - Improved version that requires token-based session authentication

### Vulnerability Explanation

Instances using IMDSv1 can be vulnerable to SSRF attacks when:
1. The instance has outbound Security Group rules that allow traffic to the metadata service (169.254.169.254:80)
2. An application running on the instance has SSRF vulnerabilities

If these conditions are met, an attacker could trick the application into making requests to the metadata service, potentially exposing IAM credentials and other sensitive information.

## Remediation Recommendations

### Recommended Approach: Enable IMDSv2

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-example \
  --http-tokens required \
  --http-endpoint enabled
```

### Alternative Approach: Block Metadata Access via Security Groups

Modify Security Group rules to block outbound traffic to 169.254.169.254 on port 80.

## Severity Assessment: HIGH

The use of IMDSv1 without compensating controls presents a HIGH severity risk due to:

1. **Widespread issue**: Affects a large percentage of instances
2. **Serious consequences**: Potential exposure of IAM credentials leading to account compromise
3. **Ease of exploitation**: Can be exploited through common web application vulnerabilities
4. **Limited compensating controls**: Only a small percentage of instances have SG protection
5. **Real-world precedent**: Similar vulnerabilities have been exploited in major breaches (e.g., Capital One)

## Output Files

The tool generates two output files:
- Text report (*.txt): Human-readable format suitable for review and documentation
- JSON report (*.json): Machine-readable format suitable for integration with other tools or dashboards

## License

This tool is provided for educational and professional security assessment purposes only.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.