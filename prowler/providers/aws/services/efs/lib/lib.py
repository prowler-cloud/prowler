def is_public_access_allowed(statement):
    """
    Check if the statement allows public access
    Args:
        statement: dict: Statement from the policy
    Returns:
        bool: True if the statement allows public access, False otherwise
    """
    principal = statement.get("Principal")
    if principal == "*" or (isinstance(principal, dict) and "*" in principal.values()):
        return not has_secure_conditions(statement)
    return False


def has_secure_conditions(statement):
    """
    Check if the statement has secure conditions
    Args:
        statement: dict: Statement from the policy
    Returns:
        bool: True if the statement has secure conditions, False otherwise
    """
    conditions = statement.get("Condition", {})
    allowed_conditions = {
        "aws:SourceArn",
        "aws:SourceVpc",
        "aws:SourceVpce",
        "aws:SourceOwner",
        "aws:SourceAccount",
    }
    if (
        "Bool" in conditions
        and conditions["Bool"].get("elasticfilesystem:AccessedViaMountTarget") == "true"
    ):
        return True

    # Check for conditions with nested keys
    for _, conditions_dict in conditions.items():
        for key, value in conditions_dict.items():
            if isinstance(value, dict):
                if set(value.keys()).intersection(allowed_conditions):
                    return True
            elif key in allowed_conditions:
                return True
    return False
