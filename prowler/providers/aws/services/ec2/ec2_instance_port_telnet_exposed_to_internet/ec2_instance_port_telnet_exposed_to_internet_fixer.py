from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group


class Ec2InstancePortTelnetExposedToInternetFixer(AWSFixer):
    """
    Fixer to revoke ingress rules allowing Telnet ports from any address for EC2 instances' security groups.
    """

    def __init__(self):
        super().__init__(
            description="Revoke ingress rules allowing Telnet ports from any address for EC2 instances' security groups.",
            cost_impact=False,
            cost_description=None,
            service="ec2",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "ec2:RevokeSecurityGroupIngress",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Revoke ingress rules allowing Telnet ports from any address for EC2 instances' security groups.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: resource_id, region (if finding is not provided)
        Returns:
            bool: True if the operation is successful (ingress rule revoked), False otherwise.
        """
        try:
            if finding:
                resource_id = finding.resource_id
                region = finding.region
            else:
                resource_id = kwargs.get("resource_id")
                region = kwargs.get("region")

            if not resource_id or not region:
                raise ValueError("resource_id and region are required")

            super().fix(region=region)

            regional_client = ec2_client.regional_clients[region]
            check_ports = [23]
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
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
        else:
            return True
