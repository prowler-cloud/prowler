from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.ecr.ecr_client import ecr_client


class EcrRepositoriesNotPubliclyAccessibleFixer(AWSFixer):
    """
    Fixer to remove public access from ECR repositories by deleting their policy.
    """

    def __init__(self):
        super().__init__(
            description="Remove public access from ECR repositories by deleting their policy.",
            cost_impact=False,
            cost_description=None,
            service="ecr",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "ecr:DeleteRepositoryPolicy",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Remove public access from ECR repositories by deleting their policy.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: resource_id, region (if finding is not provided)
        Returns:
            bool: True if the operation is successful (policy updated), False otherwise.
        """
        try:
            if finding:
                resource_id = finding.resource_id
                region = finding.region
            else:
                resource_id = kwargs.get("resource_id")
                region = kwargs.get("region")

            if not resource_id or not region:
                raise ValueError("resource_id and region are required")

            super().fix(region=region)

            regional_client = ecr_client.regional_clients[region]
            regional_client.delete_repository_policy(repositoryName=resource_id)
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
        else:
            return True
