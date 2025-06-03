# AWS Regions and Partitions

By default Prowler is able to scan the following AWS partitions:

    - Commercial: `aws`
    - China: `aws-cn`
    - GovCloud (US): `aws-us-gov`

???+ note
    To check the available regions for each partition and service, refer to: [aws\_regions\_by\_service.json](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/aws_regions_by_service.json)

## Scanning AWS China and GovCloud Partitions in Prowler

When scanning the China (`aws-cn`) or GovCloud (`aws-us-gov`) , ensure one of the following:

Your AWS credentials include a valid region within the desired partition.

Specify the regions to audit within that partition using the `-f/--region` flag.

???+ note
    Refer to: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html#configuring-credentials for more information about the AWS credential configuration.

### Scanning Specific Regions

To scan a particular AWS region with Prowler, use:

```console
prowler aws -f/--region eu-west-1 us-east-1
```

### AWS Credentials Configuration

For details on configuring AWS credentials, refer to the following [Botocore](https://github.com/boto/botocore) [file](https://github.com/boto/botocore/blob/22a19ea7c4c2c4dd7df4ab8c32733cba0c7597a4/botocore/data/partitions.json).

## Scanning AWS Partitions in Prowler

### AWS China

To scan an account in the AWS China partition (`aws-cn`):

    - By using the `-f/--region` flag:

    ```
    prowler aws --region cn-north-1 cn-northwest-1
    ```

    - By using the region configured in your AWS profile at `~/.aws/credentials` or `~/.aws/config`:

    ```
    [default]
    aws_access_key_id = XXXXXXXXXXXXXXXXXXX
    aws_secret_access_key = XXXXXXXXXXXXXXXXXXX
    region = cn-north-1
    ```

???+ note
    With this configuration, all partition regions will be scanned without needing the `-f/--region` flag

### AWS GovCloud (US)

To scan an account in the AWS GovCloud (US) partition (`aws-us-gov`):

    - By using the `-f/--region` flag:

    ```
    prowler aws --region us-gov-east-1 us-gov-west-1
    ```

    - By using the region configured in your AWS profile at `~/.aws/credentials` or `~/.aws/config`:

    ```
    [default]
    aws_access_key_id = XXXXXXXXXXXXXXXXXXX
    aws_secret_access_key = XXXXXXXXXXXXXXXXXXX
    region = us-gov-east-1
    ```

???+ note
    With this configuration, all partition regions will be scanned without needing the `-f/--region` flag

### AWS ISO (US \& Europe)

The AWS ISO partitions—commonly referred to as "secret partitions"—are air-gapped from the Internet, and Prowler does not have a built-in way to scan them. To audit an AWS ISO partition, manually update [aws\_regions\_by\_service.json](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/aws_regions_by_service.json) to include the partition, region, and services. For example:

```json
"iam": {
    "regions": {
    "aws": [
        "eu-west-1",
        "us-east-1",
    ],
    "aws-cn": [
        "cn-north-1",
        "cn-northwest-1"
    ],
    "aws-us-gov": [
        "us-gov-east-1",
        "us-gov-west-1"
    ],
    "aws-iso": [
        "aws-iso-global",
        "us-iso-east-1",
        "us-iso-west-1"
    ],
    "aws-iso-b": [
        "aws-iso-b-global",
        "us-isob-east-1"
    ],
    "aws-iso-e": [],
    }
},
```
