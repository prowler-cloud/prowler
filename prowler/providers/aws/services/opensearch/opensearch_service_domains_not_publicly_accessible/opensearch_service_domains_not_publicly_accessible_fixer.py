import json
from copy import deepcopy

from prowler.lib.logger import logger
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the OpenSearch domain's resource-based policy to remove public access.
    Specifically, this fixer removes the statements that grant public access, using the same logic as the check,
    and keeps the rest of the policy, such as grants to specific accounts or trusted IPs. If no statement is left,
    the domain config is updated with an empty policy to remove the old one.
    Requires the es:DescribeDomain and es:UpdateDomainConfig permissions.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "es:DescribeDomain",
                    "es:UpdateDomainConfig"
                ],
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
        trusted_ips = opensearch_client.audit_config.get("trusted_ips", [])
        policy = json.loads(
            regional_client.describe_domain(DomainName=resource_id)["DomainStatus"][
                "AccessPolicies"
            ]
        )
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        remaining_statements = [
            statement
            for statement in statements
            if not is_policy_public(
                # is_policy_public normalizes condition keys in place, so check a copy
                {"Statement": [deepcopy(statement)]},
                opensearch_client.audited_account,
                trusted_ips=trusted_ips,
            )
        ]

        if remaining_statements:
            policy["Statement"] = remaining_statements
            access_policies = json.dumps(policy)
        else:
            access_policies = ""

        regional_client.update_domain_config(
            DomainName=resource_id,
            AccessPolicies=access_policies,
        )

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
