from prowler.lib.logger import logger
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group


def fixer(resource_id: str, region: str) -> bool:
    """
    Revokes any ingress rule allowing RDP ports (3389) from any address (0.0.0.0/0)
    for the EC2 instance's security groups.
    This fixer will only be triggered if the check identifies RDP ports open to the Internet.
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
        resource_id (str): The EC2 instance ID.
        region (str): The AWS region where the EC2 instance exists.
    Returns:
        bool: True if the operation is successful (ingress rule revoked), False otherwise.
    """
    try:
        regional_client = ec2_client.regional_clients[region]
        check_ports = [3389]
        for instance in ec2_client.instances:
            if instance.id == resource_id:
                for sg in ec2_client.security_groups.values():
                    if sg.id in instance.security_groups:
                        for ingress_rule in sg.ingress_rules:
                            if check_security_group(
                                ingress_rule, "tcp", check_ports, any_address=True
                            ):
                                regional_client.revoke_security_group_ingress(
                                    GroupId=sg.id,
                                    IpPermissions=[ingress_rule],
                                )

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
