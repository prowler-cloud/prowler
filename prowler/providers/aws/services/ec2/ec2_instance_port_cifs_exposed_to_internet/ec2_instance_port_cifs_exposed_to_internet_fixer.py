from prowler.lib.logger import logger
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Revokes any ingress rule allowing CIFS ports (139, 445) from any address (0.0.0.0/0)
    for the EC2 instance's security groups.
    This fixer will only be triggered if the check identifies CIFS ports open to the Internet.
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

        response = regional_client.describe_instances(InstanceIds=[resource_id])

        security_group_ids = [
            sg["GroupId"]
            for sg in response["Reservations"][0]["Instances"][0]["SecurityGroups"]
        ]

        for sg_id in security_group_ids:
            ip_permissions = regional_client.describe_security_groups(GroupIds=[sg_id])[
                "SecurityGroups"
            ][0]["IpPermissions"]

            for permission in ip_permissions:
                if permission.get("FromPort") == 139:
                    if any(
                        ip_range.get("CidrIp") == "0.0.0.0/0"
                        for ip_range in permission.get("IpRanges", [])
                    ):
                        regional_client.revoke_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions=[
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 139,
                                    "ToPort": 139,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                },
                            ],
                        )
                    if any(
                        ip_range.get("CidrIpv6") == "::/0"
                        for ip_range in permission.get("Ipv6Ranges", [])
                    ):
                        regional_client.revoke_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions=[
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 139,
                                    "ToPort": 139,
                                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                                },
                            ],
                        )

            for permission in ip_permissions:
                if permission.get("FromPort") == 445:
                    if any(
                        ip_range.get("CidrIp") == "0.0.0.0/0"
                        for ip_range in permission.get("IpRanges", [])
                    ):
                        regional_client.revoke_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions=[
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 445,
                                    "ToPort": 445,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                },
                            ],
                        )
                    if any(
                        ip_range.get("CidrIpv6") == "::/0"
                        for ip_range in permission.get("Ipv6Ranges", [])
                    ):
                        regional_client.revoke_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions=[
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 445,
                                    "ToPort": 445,
                                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                                },
                            ],
                        )

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
