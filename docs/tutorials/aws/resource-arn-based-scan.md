# Resource ARNs based Scan

Prowler allows you to scan only the resources with specific AWS Resource ARNs. This can be done with the flag `--resource-arn` followed by one or more [Amazon Resource Names (ARNs)](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html) separated by space:

```
prowler aws --resource-arn arn:aws:iam::012345678910:user/test arn:aws:ec2:us-east-1:123456789012:vpc/vpc-12345678
```

This example will only scan the two resources with those ARNs.
