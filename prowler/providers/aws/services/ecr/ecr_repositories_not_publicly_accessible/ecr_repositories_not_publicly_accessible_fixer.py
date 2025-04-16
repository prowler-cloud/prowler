from prowler.lib.logger import logger
from prowler.providers.aws.services.ecr.ecr_client import ecr_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the ECR repository's policy to remove public access.
    Specifically, this fixer delete the policy that had public access.
    Requires the ecr:DeleteRepositoryPolicy permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ecr:DeleteRepositoryPolicy",
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

        regional_client.delete_repository_policy(repositoryName=resource_id)

    except Exception as error:
        logger.exception(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
