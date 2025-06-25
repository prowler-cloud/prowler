from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.codeartifact.codeartifact_client import (
    codeartifact_client,
)


class CodeartifactPackagesExternalPublicPublishingDisabledFixer(AWSFixer):
    """
    Fixer for modifying the CodeArtifact package's configuration to restrict public access.
    """

    def __init__(self):
        super().__init__(
            description="Modify the CodeArtifact package's configuration to restrict public access.",
            cost_impact=False,
            cost_description=None,
            service="codeartifact",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "codeartifact:PutPackageOriginConfiguration",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Modify the CodeArtifact package's configuration to restrict public access.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region, resource_id (if finding is not provided)
        Returns:
            bool: True if the operation is successful (configuration updated), False otherwise.
        """
        try:
            if finding:
                region = finding.region
                resource_id = finding.resource_id
            else:
                region = kwargs.get("region")
                resource_id = kwargs.get("resource_id")

            if not region or not resource_id:
                raise ValueError("Region and resource_id are required")

            super().fix(region=region, resource_id=resource_id)

            domain_name, package_name = resource_id.split("/")
            regional_client = codeartifact_client.regional_clients[region]

            for repository in codeartifact_client.repositories.values():
                if repository.domain_name == domain_name:
                    for package in repository.packages:
                        if package.name == package_name:
                            publish_value = (
                                package.origin_configuration.restrictions.publish.value
                            )
                            regional_client.put_package_origin_configuration(
                                domain=domain_name,
                                repository=repository.name,
                                format=package.format,
                                package=package_name,
                                restrictions={
                                    "publish": publish_value,
                                    "upstream": "BLOCK",
                                },
                            )
            return True
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
