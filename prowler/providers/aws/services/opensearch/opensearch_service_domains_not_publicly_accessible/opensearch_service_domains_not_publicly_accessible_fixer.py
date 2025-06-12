from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class OpensearchServiceDomainsNotPubliclyAccessibleFixer(AWSFixer):
    """
    Fixer to remove public access from OpenSearch domains.
    """

    def __init__(self):
        super().__init__(
            description="Remove public access from OpenSearch domains.",
            cost_impact=False,
            cost_description=None,
            service="opensearch",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "es:UpdateDomainConfig",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Remove public access from OpenSearch domains.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region, resource_id (if finding is not provided)
        Returns:
            bool: True if public access is removed, False otherwise.
        """
        try:
            if finding:
                region = finding.region
                resource_id = finding.resource_id
            else:
                region = kwargs.get("region")
                resource_id = kwargs.get("resource_id")

            if not region or not resource_id:
                raise ValueError("region and resource_id are required")

            super().fix(region=region, resource_id=resource_id)

            regional_client = opensearch_client.regional_clients[region]
            regional_client.update_domain_config(
                DomainName=resource_id,
                AccessPolicies="",
            )
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
        else:
            return True
