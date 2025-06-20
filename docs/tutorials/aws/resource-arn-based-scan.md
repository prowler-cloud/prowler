# Resource ARN-based Scannnig

Prowler enables scanning of resources based on specific AWS Resource ARNs.

## Resource ARN-Based Scanning

Prowler enables scanning of resources based on specific AWS Resource [Amazon Resource Names (ARNs)](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html). To perform this scan, use the designated flag `--resource-arn` followed by one or more ARNs, separated by spaces.

```
prowler aws --resource-arn arn:aws:iam::012345678910:user/test arn:aws:ec2:us-east-1:123456789012:vpc/vpc-12345678
```

Example: This configuration scans only the specified two resources using their ARNs.
