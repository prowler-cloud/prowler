import json

from prowler.lib.logger import logger
from prowler.providers.aws.services.ecr.ecr_client import ecr_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the ECR repository's policy to remove public access.
    Specifically, this fixer replaces the policy allowing public access
    with a trusted access policy for the AWS account. Requires the ecr:SetRepositoryPolicy permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ecr:SetRepositoryPolicy",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The ECR repository name.
        region (str): AWS region where the ECR repository exists.
    Returns:
        bool: True if the operation is successful (policy updated), False otherwise.
    """
    try:
        regional_client = ecr_client.regional_clients[region]
        account_id = ecr_client.audited_account
        audited_partition = ecr_client.audited_partition
        trusted_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ProwlerFixerStatement",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:{audited_partition}:iam::{account_id}:root"
                    },
                    "Action": "ecr:*",
                }
            ],
        }

        regional_client.set_repository_policy(
            repositoryName=resource_id, policyText=json.dumps(trusted_policy)
        )

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
