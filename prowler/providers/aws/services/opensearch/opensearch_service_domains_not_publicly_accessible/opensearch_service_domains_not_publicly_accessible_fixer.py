from prowler.lib.logger import logger
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the OpenSearch domain's resource-based policy to remove public access.
    Specifically, this fixer update the domain config and add an empty policy to remove the old one.
    Requires the es:UpdateDomainConfig permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "es:UpdateDomainConfig",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The OpenSearch domain name.
        region (str): AWS region where the OpenSearch domain exists.
    Returns:
        bool: True if the operation is successful (policy updated), False otherwise.
    """
    try:
        regional_client = opensearch_client.regional_clients[region]

        regional_client.update_domain_config(
            DomainName=resource_id,
            AccessPolicies="",
        )

    except Exception as error:
        logger.exception(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
