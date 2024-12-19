from prowler.lib.logger import logger
from prowler.providers.aws.services.codeartifact.codeartifact_client import (
    codeartifact_client,
)


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the CodeArtifact package's configuration to restrict public access.
    Specifically, this fixer changes the package's configuration to block public access by
    setting restrictions on the "publish" and "upstream" actions.
    Requires the codeartifact:PutPackageOriginConfiguration permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "codeartifact:PutPackageOriginConfiguration",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The CodeArtifact package name in the format "domain_name/package_name".
        region (str): AWS region where the CodeArtifact package exists.
    Returns:
        bool: True if the operation is successful (configuration updated), False otherwise.
    """
    try:
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

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
