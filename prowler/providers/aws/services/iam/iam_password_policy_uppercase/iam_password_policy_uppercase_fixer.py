from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.iam.iam_client import iam_client


class IamPasswordPolicyUppercaseFixer(AWSFixer):
    """
    Fixer to enable IAM password policy to require uppercase characters (or configurable value).
    """

    def __init__(self):
        super().__init__(
            description="Enable IAM password policy to require uppercase characters (or configurable value).",
            cost_impact=False,
            cost_description=None,
            service="iam",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:UpdateAccountPasswordPolicy",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Enable IAM password policy to require uppercase characters (or configurable value).
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: resource_id (account id, if finding is not provided)
        Returns:
            bool: True if IAM password policy is updated, False otherwise
        """
        try:
            if finding:
                resource_id = finding.resource_id
            else:
                resource_id = kwargs.get("resource_id")

            if not resource_id:
                raise ValueError("resource_id (account id) is required")

            super().fix()

            iam_client.client.update_account_password_policy(
                MinimumPasswordLength=iam_client.password_policy.length,
                RequireSymbols=iam_client.password_policy.symbols,
                RequireNumbers=iam_client.password_policy.numbers,
                RequireUppercaseCharacters=iam_client.fixer_config.get(
                    "iam_password_policy", {}
                ).get("RequireUppercaseCharacters", True),
                RequireLowercaseCharacters=iam_client.password_policy.lowercase,
                AllowUsersToChangePassword=iam_client.password_policy.allow_change,
                MaxPasswordAge=iam_client.password_policy.max_age,
                PasswordReusePrevention=iam_client.password_policy.reuse_prevention,
                HardExpiry=iam_client.password_policy.hard_expiry,
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
        else:
            return True
