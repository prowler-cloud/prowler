# Mutelisting
Sometimes you may find resources that are intentionally configured in a certain way that may be a bad practice but it is all right with it, for example an AWS S3 Bucket open to the internet hosting a web site, or an AWS Security Group with an open port needed in your use case.

Mutelist option works along with other options and will modify the output in the following way if the finding is muted:

- JSON-OCSF: `status_id` is `Suppressed`.
- CSV: `muted` is `True`. The field `status` will keep the original status, `MANUAL`, `PASS` or `FAIL`, of the finding.


## How the Mutelist Works

The **Mutelist** uses both "AND" and "OR" logic to determine which resources, checks, regions, and tags should be muted. For each check, the Mutelist evaluates whether the account, region, and resource match the specified criteria using "AND" logic. If tags are specified, the Mutelist can apply either "AND" or "OR" logic.

If any of the criteria do not match, the check is not muted.

???+ note
    Remember that mutelist can be used with regular expressions.

## Mutelist Specification

???+ note
    - For Azure provider, the Account ID is the Subscription Name and the Region is the Location.
    - For GCP provider, the Account ID is the Project ID and the Region is the Zone.
    - For Kubernetes provider, the Account ID is the Cluster Name and the Region is the Namespace.

The Mutelist file uses the [YAML](https://en.wikipedia.org/wiki/YAML) format with the following syntax:

```yaml
### Account, Check and/or Region can be * to apply for all the cases.
### Resources and tags are lists that can have either Regex or Keywords.
### Tags is an optional list that matches on tuples of 'key=value' and are "ANDed" together.
### Use an alternation Regex to match one of multiple tags with "ORed" logic.
### For each check you can except Accounts, Regions, Resources and/or Tags.
###########################  MUTELIST EXAMPLE  ###########################
Mutelist:
  Accounts:
    "123456789012":
      Checks:
        "iam_user_hardware_mfa_enabled":
          Regions:
            - "us-east-1"
          Resources:
            - "user-1"           # Will mute user-1 in check iam_user_hardware_mfa_enabled
            - "user-2"           # Will mute user-2 in check iam_user_hardware_mfa_enabled
        "ec2_*":
          Regions:
            - "*"
          Resources:
            - "*"                 # Will mute every EC2 check in every account and region
        "*":
          Regions:
            - "*"
          Resources:
            - "test"
          Tags:
            - "test=test"         # Will mute every resource containing the string "test" and the tags 'test=test' and
            - "project=test|project=stage" # either of ('project=test' OR project=stage) in account 123456789012 and every region
        "*":
            Regions:
              - "*"
            Resources:
              - "test"
            Tags:
              - "test=test"
              - "project=test"    # This will mute every resource containing the string "test" and BOTH tags at the same time.
        "*":
            Regions:
              - "*"
            Resources:
              - "test"
            Tags:                 # This will mute every resource containing the string "test" and the ones that contain EITHER the `test=test` OR `project=test` OR `project=dev`
              - "test=test|project=(test|dev)"
        "*":
            Regions:
              - "*"
            Resources:
              - "test"
            Tags:
              - "test=test"       # This will mute every resource containing the string "test" and the tags `test=test` and either `project=test` OR `project=stage` in every account and region.
              - "project=test|project=stage"

    "*":
      Checks:
        "s3_bucket_object_versioning":
          Regions:
            - "eu-west-1"
            - "us-east-1"
          Resources:
            - "ci-logs"           # Will mute bucket "ci-logs" AND ALSO bucket "ci-logs-replica" in specified check and regions
            - "logs"              # Will mute EVERY BUCKET containing the string "logs" in specified check and regions
            - ".+-logs"           # Will mute all buckets containing the terms ci-logs, qa-logs, etc. in specified check and regions
        "ecs_task_definitions_no_environment_secrets":
          Regions:
            - "*"
          Resources:
            - "*"
          Exceptions:
            Accounts:
              - "0123456789012"
            Regions:
              - "eu-west-1"
              - "eu-south-2"        # Will mute every resource in check ecs_task_definitions_no_environment_secrets except the ones in account 0123456789012 located in eu-south-2 or eu-west-1
        "*":
          Regions:
            - "*"
          Resources:
            - "*"
          Tags:
            - "environment=dev"    # Will mute every resource containing the tag 'environment=dev' in every account and region

    "123456789012":
      Checks:
        "*":
          Regions:
            - "*"
          Resources:
            - "*"
          Exceptions:
            Resources:
              - "test"
            Tags:
              - "environment=prod"   # Will mute every resource except in account 123456789012 except the ones containing the string "test" and tag environment=prod

    "*":
      Checks:
        "ec2_*":
          Regions:
            - "*"
          Resources:
            - "test-resource" # Will mute the resource "test-resource" in all accounts and regions for whatever check from the EC2 service
```

### Account, Check, Region, Resource, and Tag

| Field | Description | Logic |
|----------|----------|----------|
| `account_id`    | Use `*` to apply the mutelist to all accounts.    | `ANDed`    |
| `check_name`    | The name of the Prowler check. Use `*` to apply the mutelist to all checks, or `service_*` to apply it to all service's checks.    | `ANDed`    |
| `region`    | The region identifier. Use `*` to apply the mutelist to all regions.    | `ANDed`    |
| `resource`    | The resource identifier. Use `*` to apply the mutelist to all resources.    | `ANDed`    |
| `tag`    | The tag value.    | `ORed`    |


## How to Use the Mutelist

To use the Mutelist, you need to specify the path to the Mutelist YAML file using the `-w` or `--mutelist-file` option when running Prowler:

```
prowler <provider> -w mutelist.yaml
```

Replace `<provider>` with the appropriate provider name.

## Considerations

- The Mutelist can be used in combination with other Prowler options, such as the `--service` or `--checks` option, to further customize the scanning process.
- Make sure to review and update the Mutelist regularly to ensure it reflects the desired exclusions and remains up to date with your infrastructure.


## AWS Mutelist
### Mute specific AWS regions
If you want to mute failed findings only in specific regions, create a file with the following syntax and run it with `prowler aws -w mutelist.yaml`:

    Mutelist:
      Accounts:
      "*":
        Checks:
          "*":
            Regions:
              - "ap-southeast-1"
              - "ap-southeast-2"
            Resources:
              - "*"

### Default Mutelist
For the AWS Provider, Prowler is executed with a default AWS Mutelist with the AWS Resources that should be muted such as all resources created by AWS Control Tower when setting up a landing zone that can be found in [AWS Documentation](https://docs.aws.amazon.com/controltower/latest/userguide/shared-account-resources.html).
You can see this Mutelist file in [`prowler/config/aws_mutelist.yaml`](https://github.com/prowler-cloud/prowler/blob/master/prowler/config/aws_mutelist.yaml).

### Supported Mutelist Locations

The mutelisting flag supports the following AWS locations when using the AWS Provider:

#### AWS S3 URI
You will need to pass the S3 URI where your Mutelist YAML file was uploaded to your bucket:
```
prowler aws -w s3://<bucket>/<prefix>/mutelist.yaml
```
???+ note
    Make sure that the used AWS credentials have `s3:GetObject` permissions in the S3 path where the mutelist file is located.

#### AWS DynamoDB Table ARN

You will need to pass the DynamoDB Mutelist Table ARN:

```
prowler aws -w arn:aws:dynamodb:<region_name>:<account_id>:table/<table_name>
```

1. The DynamoDB Table must have the following String keys:
<img src="../img/mutelist-keys.png"/>

- The Mutelist Table must have the following columns:
    - Accounts (String): This field can contain either an Account ID or an `*` (which applies to all the accounts that use this table as an mutelist).
    - Checks (String): This field can contain either a Prowler Check Name or an `*` (which applies to all the scanned checks).
    - Regions (List): This field contains a list of regions where this mutelist rule is applied (it can also contains an `*` to apply all scanned regions).
    - Resources (List): This field contains a list of regex expressions that applies to the resources that are wanted to be muted.
    - Tags (List): -Optional- This field contains a list of tuples in the form of 'key=value' that applies to the resources tags that are wanted to be muted.
    - Exceptions (Map): -Optional- This field contains a map of lists of accounts/regions/resources/tags that are wanted to be excepted in the mutelist.

The following example will mute all resources in all accounts for the EC2 checks in the regions `eu-west-1` and `us-east-1` with the tags `environment=dev` and `environment=prod`, except the resources containing the string `test` in the account `012345678912` and region `eu-west-1` with the tag `environment=prod`:

<img src="../img/mutelist-row.png"/>

???+ note
    Make sure that the used AWS credentials have `dynamodb:PartiQLSelect` permissions in the table.

#### AWS Lambda ARN

You will need to pass the AWS Lambda Function ARN:

```
prowler aws -w arn:aws:lambda:REGION:ACCOUNT_ID:function:FUNCTION_NAME
```

Make sure that the credentials that Prowler uses can invoke the Lambda Function:

```
- PolicyName: GetMuteList
  PolicyDocument:
    Version: '2012-10-17'
    Statement:
      - Action: 'lambda:InvokeFunction'
        Effect: Allow
        Resource: arn:aws:lambda:REGION:ACCOUNT_ID:function:FUNCTION_NAME
```

The Lambda Function can then generate an Mutelist dynamically. Here is the code an example Python Lambda Function that
generates an Mutelist:

```
def handler(event, context):
  checks = {}
  checks["vpc_flow_logs_enabled"] = { "Regions": [ "*" ], "Resources": [ "" ], Optional("Tags"): [ "key:value" ] }

  al = { "Mutelist": { "Accounts": { "*": { "Checks": checks } } } }
  return al
```
