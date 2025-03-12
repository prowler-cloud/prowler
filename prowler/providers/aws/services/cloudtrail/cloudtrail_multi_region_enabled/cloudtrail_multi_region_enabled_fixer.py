from prowler.lib.logger import logger
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)


def fixer(region):
    """
    NOTE: Define the S3 bucket name in the fixer_config.yaml file.
    Enable CloudTrail in a region. Requires the cloudtrail:CreateTrail permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "cloudtrail:CreateTrail",
                "Resource": "*"
            }
        ]
    }
    Args:
        region (str): AWS region
    Returns:
        bool: True if CloudTrail is enabled, False otherwise
    """
    try:
        cloudtrail_fixer_config = cloudtrail_client.fixer_config.get(
            "cloudtrail_multi_region_enabled", {}
        )
        regional_client = cloudtrail_client.regional_clients[region]
        args = {
            "Name": cloudtrail_fixer_config.get("TrailName", "DefaultTrail"),
            "S3BucketName": cloudtrail_fixer_config.get("S3BucketName"),
            "IsMultiRegionTrail": cloudtrail_fixer_config.get(
                "IsMultiRegionTrail", True
            ),
            "EnableLogFileValidation": cloudtrail_fixer_config.get(
                "EnableLogFileValidation", True
            ),
        }
        if cloudtrail_fixer_config.get("CloudWatchLogsLogGroupArn"):
            args["CloudWatchLogsLogGroupArn"] = cloudtrail_fixer_config.get(
                "CloudWatchLogsLogGroupArn"
            )
        if cloudtrail_fixer_config.get("CloudWatchLogsRoleArn"):
            args["CloudWatchLogsRoleArn"] = cloudtrail_fixer_config.get(
                "CloudWatchLogsRoleArn"
            )
        if cloudtrail_fixer_config.get("KmsKeyId"):
            args["KmsKeyId"] = cloudtrail_fixer_config.get("KmsKeyId")
        regional_client.create_trail(**args)
    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
