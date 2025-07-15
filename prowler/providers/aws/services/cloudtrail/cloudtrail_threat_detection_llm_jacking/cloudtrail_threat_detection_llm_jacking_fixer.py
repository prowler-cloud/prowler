import json
from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.iam.iam_client import iam_client


class CloudtrailThreatDetectionLlmJackingFixer(AWSFixer):
    """
    Fixer for restricting access to a compromised AWS entity by attaching a deny-all inline policy to the user or role.
    """

    def __init__(self):
        super().__init__(
            description="Restricts access to a compromised AWS entity by attaching a deny-all inline policy to the user or role.",
            cost_impact=False,
            cost_description=None,
            service="cloudtrail",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:PutUserPolicy",
                            "iam:PutRolePolicy",
                        ],
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Restricts access to a compromised AWS entity by attaching a deny-all inline policy to the user or role.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix (should have resource_arn)
            **kwargs: resource_arn (if finding is not provided)
        Returns:
            bool: True if the fix was applied successfully, False otherwise.
        """
        try:
            if finding:
                resource_arn = getattr(finding, "resource_arn", None)
            else:
                resource_arn = kwargs.get("resource_arn")

            if not resource_arn:
                raise ValueError("resource_arn is required")

            super().fix(resource_arn=resource_arn)

            if ":user/" in resource_arn:
                entity_type = "user"
                entity_name = resource_arn.split("/")[-1]
            elif ":role/" in resource_arn:
                entity_type = "role"
                entity_name = resource_arn.split("/")[-1]
            else:
                return False

            deny_policy = {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
            }

            policy_name = "DenyAllAccess"

            if entity_type == "user":
                iam_client.client.put_user_policy(
                    UserName=entity_name,
                    PolicyName=policy_name,
                    PolicyDocument=json.dumps(deny_policy),
                )
                logger.info(f"Applied Deny policy to user {entity_name}")

            elif entity_type == "role":
                iam_client.client.put_role_policy(
                    RoleName=entity_name,
                    PolicyName=policy_name,
                    PolicyDocument=json.dumps(deny_policy),
                )
                logger.info(f"Applied Deny policy to role {entity_name}")

            return True

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
