import json

from prowler.lib.logger import logger
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the OpenSearch domain's resource-based policy to remove public access and replace it with trusted account access.
    Specifically, this fixer checks if any statement has a public Principal (e.g., "*" or "AWS": "*")
    and replaces it with the ARN of the trusted AWS account. Requires the es:UpdateDomainConfig permission.
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
        resource_id (str): The OpenSearch domain name or ARN.
        region (str): AWS region where the OpenSearch domain exists.
    Returns:
        bool: True if the operation is successful (policy updated), False otherwise.
    """
    try:
        account_id = opensearch_client.audited_account

        regional_client = opensearch_client.regional_clients[region]

        domain_config = regional_client.describe_domain_config(DomainName=resource_id)
        policy = json.loads(domain_config["DomainConfig"]["AccessPolicies"]["Options"])

        for statement in policy.get("Statement", []):
            if "Principal" in statement and (
                "*" in statement["Principal"]
                or (
                    "AWS" in statement["Principal"]
                    and "*" in statement["Principal"]["AWS"]
                )
                or (
                    "CanonicalUser" in statement["Principal"]
                    and "*" in statement["Principal"]["CanonicalUser"]
                )
            ):
                statement["Principal"] = {"AWS": f"arn:aws:iam::{account_id}:root"}
                statement["Action"] = "es:*"
                statement["Resource"] = (
                    f"arn:aws:es:{region}:{account_id}:domain/{resource_id}/*"
                )

        regional_client.update_domain_config(
            DomainName=resource_id,
            AccessPolicies=json.dumps(policy),
        )

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
