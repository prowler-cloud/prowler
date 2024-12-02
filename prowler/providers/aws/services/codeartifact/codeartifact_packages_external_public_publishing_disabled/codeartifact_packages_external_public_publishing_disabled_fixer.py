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
        resource_id (str): The CodeArtifact package name.
        region (str): AWS region where the CodeArtifact package exists.
    Returns:
        bool: True if the operation is successful (configuration updated), False otherwise.
    """
    try:
        regional_client = codeartifact_client.regional_clients[region]
        regional_client.put_package_origin_configuration(
            package=resource_id,
            restrictions={"publish": "ALLOW", "upstream": "BLOCK"},
        )

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
