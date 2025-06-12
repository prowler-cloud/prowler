from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group


class Ec2SecuritygroupAllowIngressFromInternetToHighRiskTcpPortsFixer(AWSFixer):
    """
    Fixer to revoke ingress rules allowing high risk ports from any address for security groups.
    """

    def __init__(self):
        super().__init__(
            description="Revoke ingress rules allowing high risk ports from any address for security groups.",
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
        Revoke ingress rules allowing high risk ports from any address for security groups.
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
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
        else:
            return True
