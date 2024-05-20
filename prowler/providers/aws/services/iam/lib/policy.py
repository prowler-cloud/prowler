def is_policy_cross_account(policy: dict, audited_account: str) -> bool:
    """
    is_policy_cross_account checks if the policy allows cross-account access.
    Args:
        policy (dict): The policy to check.
        audited_account (str): The account to check if it has access.
    Returns:
        bool: True if the policy allows cross-account access, False otherwise.
    """
    if policy and "Statement" in policy:
        if isinstance(policy["Statement"], list):
            for statement in policy["Statement"]:
                if statement["Effect"] == "Allow" and "AWS" in statement["Principal"]:
                    if isinstance(statement["Principal"]["AWS"], list):
                        for aws_account in statement["Principal"]["AWS"]:
                            if audited_account not in aws_account or "*" == aws_account:
                                return True
                    else:
                        if (
                            audited_account not in statement["Principal"]["AWS"]
                            or "*" == statement["Principal"]["AWS"]
                        ):
                            return True
        else:
            statement = policy["Statement"]
            if statement["Effect"] == "Allow" and "AWS" in statement["Principal"]:
                if isinstance(statement["Principal"]["AWS"], list):
                    for aws_account in statement["Principal"]["AWS"]:
                        if audited_account not in aws_account or "*" == aws_account:
                            return True
                else:
                    if (
                        audited_account not in statement["Principal"]["AWS"]
                        or "*" == statement["Principal"]["AWS"]
                    ):
                        return True
    return False


def is_policy_public(policy: dict) -> bool:
    """
    is_policy_public checks if the policy is publicly accessible.
    If the "Principal" element value is set to { "AWS": "*" } and the policy statement is not using any Condition clauses to filter the access, the selected policy is publicly accessible.
    Args:
        policy (dict): The policy to check.
        Returns:
        bool: True if the policy is publicly accessible, False otherwise.
    """
    if policy and "Statement" in policy:
        for statement in policy["Statement"]:
            if (
                "Principal" in statement
                and (
                    "*" == statement["Principal"]
                    or "arn:aws:iam::*:root" in statement["Principal"]
                )
                and "Condition" not in statement
            ):
                return True
            elif "Principal" in statement and "AWS" in statement["Principal"]:
                if isinstance(statement["Principal"]["AWS"], str):
                    principals = [statement["Principal"]["AWS"]]
                else:
                    principals = statement["Principal"]["AWS"]
                for principal_arn in principals:
                    if (
                        principal_arn == "*" or principal_arn == "arn:aws:iam::*:root"
                    ) and "Condition" not in statement:
                        return True
    return False
