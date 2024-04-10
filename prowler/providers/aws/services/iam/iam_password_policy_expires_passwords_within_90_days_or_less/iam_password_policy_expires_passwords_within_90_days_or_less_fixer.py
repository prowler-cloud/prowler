from prowler.lib.logger import logger
from prowler.providers.aws.services.iam.iam_client import iam_client


def fixer(resource_id: str) -> bool:
    """
    Enable IAM password policy to expire passwords within 90 days or less or the configurable value in prowler/config/config_fixer.yaml.
    Requires the iam:UpdateAccountPasswordPolicy permission:
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
    Returns:
        bool: True if IAM password policy is updated, False otherwise
    """
    try:
        iam_client.client.update_account_password_policy(
            MinimumPasswordLength=iam_client.fixer_config.get(
                "MinimumPasswordLength", 14
            ),
            RequireSymbols=iam_client.fixer_config.get("RequireSymbols", True),
            RequireNumbers=iam_client.fixer_config.get("RequireNumbers", True),
            RequireUppercaseCharacters=iam_client.fixer_config.get(
                "RequireUppercaseCharacters", True
            ),
            RequireLowercaseCharacters=iam_client.fixer_config.get(
                "RequireLowercaseCharacters", True
            ),
            AllowUsersToChangePassword=iam_client.fixer_config.get(
                "AllowUsersToChangePassword", True
            ),
            MaxPasswordAge=iam_client.fixer_config.get("MaxPasswordAge", 90),
            PasswordReusePrevention=iam_client.fixer_config.get(
                "PasswordReusePrevention", 24
            ),
            HardExpiry=iam_client.fixer_config.get("HardExpiry", True),
        )
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
