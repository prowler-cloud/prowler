# AWS Regions and Partitions

By default Prowler is able to scan the following AWS partitions:
- Commercial: `aws`
- China: `aws-cn`
- GovCloud (US): `aws-us-gov`

> To check the available regions for each partition and service please refer to the following document [aws_regions_by_service.json](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/aws_regions_by_service.json)

It is important to take into consideration that to scan the China (`aws-cn`) or GovCloud (`aws-us-gov`) partitions it is either required to have a valid region for that partition in your AWS credentials (Refer to https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html#configuring-credentials for more information) or to specify the regions you want to audit for that partition using the `-f/--region` flag.

You can get more information about the available partitions and regions in the following [Botocore](https://github.com/boto/botocore) file https://github.com/boto/botocore/blob/22a19ea7c4c2c4dd7df4ab8c32733cba0c7597a4/botocore/data/partitions.json
## AWS China

To scan your AWS Account in the China partition (`aws-cn`):

- Using the `-f/--region` flag:
```
prowler aws --region cn-north-1 cn-northwest-1
```
- Using the region configured in your AWS profile at `~/.aws/credentials` or `~/.aws/config`:
```
[default]
aws_access_key_id = XXXXXXXXXXXXXXXXXXX
aws_secret_access_key = XXXXXXXXXXXXXXXXXXX
region = cn-north-1
```
> With this option all the partition regions will be scanned without the need of use the `-f/--region` flag


## AWS GovCloud (US)

To scan your AWS Account in the GovCloud (US) partition (`aws-us-gov`):

- Using the `-f/--region` flag:
```
prowler aws --region us-gov-east-1 us-gov-west-1
```
- Using the region configured in your AWS profile at `~/.aws/credentials` or `~/.aws/config`:
```
[default]
aws_access_key_id = XXXXXXXXXXXXXXXXXXX
aws_secret_access_key = XXXXXXXXXXXXXXXXXXX
region = us-gov-east-1
```
> With this option all the partition regions will be scanned without the need of use the `-f/--region` flag


## AWS ISO (US & Europe)

For the AWS ISO partitions, which are known as "secret partitions" and are air-gapped from the internet there is no builtin way to scanned it. In this scenario if you want to audit an AWS Account in one of the AWS ISO partitions you should manually update the [aws_regions_by_service.json](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/aws_regions_by_service.json) and include the partition, region and services, e.g.:
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
