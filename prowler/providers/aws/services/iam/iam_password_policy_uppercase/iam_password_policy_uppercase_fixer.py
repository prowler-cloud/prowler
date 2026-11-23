from prowler.lib.logger import logger
from prowler.providers.aws.services.iam.iam_client import iam_client


def fixer(resource_id: str) -> bool:
    """
    Enable IAM password policy to require uppercase characters or the configurable value in prowler/config/fixer_config.yaml.
    Requires the iam:UpdateAccountPasswordPolicy permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:UpdateAccountPasswordPolicy",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): AWS account ID
    Returns:
        bool: True if IAM password policy is updated, False otherwise
    """
    try:
        password_policy = {
            "MinimumPasswordLength": iam_client.password_policy.length,
            "RequireSymbols": iam_client.password_policy.symbols,
            "RequireNumbers": iam_client.password_policy.numbers,
            "RequireUppercaseCharacters": iam_client.fixer_config.get(
                "iam_password_policy", {}
            ).get("RequireUppercaseCharacters", True),
            "RequireLowercaseCharacters": iam_client.password_policy.lowercase,
            "AllowUsersToChangePassword": iam_client.password_policy.allow_change,
            "MaxPasswordAge": iam_client.password_policy.max_age or None,
            "PasswordReusePrevention": (
                iam_client.password_policy.reuse_prevention or None
            ),
            "HardExpiry": iam_client.password_policy.hard_expiry,
        }
        # Optional settings that are not set in the current policy (None, or 0 for
        # MaxPasswordAge and PasswordReusePrevention) are omitted: the API rejects
        # None and values lower than 1, and an omitted value keeps them disabled
        iam_client.client.update_account_password_policy(
            **{
                key: value
                for key, value in password_policy.items()
                if value is not None
            }
        )
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
