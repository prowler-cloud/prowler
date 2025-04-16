from prowler.lib.logger import logger
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group


def fixer(resource_id: str, region: str) -> bool:
    """
    Revokes any ingress rule allowing high risk ports (25, 110, 135, 143, 445, 3000, 4333, 5000, 5500, 8080, 8088)
    from any address (0.0.0.0/0) for the security groups.
    This fixer will only be triggered if the check identifies high risk ports open to the Internet.
    Requires the ec2:RevokeSecurityGroupIngress permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ec2:RevokeSecurityGroupIngress",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The Security Group ID.
        region (str): The AWS region where the Security Group exists.
    Returns:
        bool: True if the operation is successful (ingress rule revoked), False otherwise.
    """
    try:
        regional_client = ec2_client.regional_clients[region]
        check_ports = ec2_client.audit_config.get(
            "ec2_high_risk_ports",
            [25, 110, 135, 143, 445, 3000, 4333, 5000, 5500, 8080, 8088],
        )
        for security_group in ec2_client.security_groups.values():
            if security_group.id == resource_id:
                for ingress_rule in security_group.ingress_rules:
                    if check_security_group(
                        ingress_rule, "tcp", check_ports, any_address=True
                    ):
                        regional_client.revoke_security_group_ingress(
                            GroupId=security_group.id,
                            IpPermissions=[ingress_rule],
                        )

    except Exception as error:
        logger.exception(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
