from ipaddress import ip_address, ip_network

from prowler.lib.logger import logger


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


def check_full_service_access(service: str, policy: dict) -> bool:
    """
    check_full_service_access checks if the policy allows full access to a service.
    Args:
        service (str): The service to check.
        policy (dict): The policy to check.
    Returns:
        bool: True if the policy allows full access to the service, False otherwise.
    """

    full_access = False

    if policy:
        policy_statements = policy.get("Statement", [])

        if not isinstance(policy_statements, list):
            policy_statements = [policy["Statement"]]

        for statement in policy_statements:
            if statement.get("Effect", "") == "Allow":
                resources = statement.get("Resource", [])

                if not isinstance(resources, list):
                    resources = [statement.get("Resource", [])]

                if "*" in resources:
                    if "Action" in statement:
                        actions = statement.get("Action", [])

                        if not isinstance(actions, list):
                            actions = [actions]

                        if f"{service}:*" in actions:
                            full_access = True
                            break

                    elif "NotAction" in statement:
                        not_actions = statement.get("NotAction", [])

                        if not isinstance(not_actions, list):
                            not_actions = [not_actions]

                        if f"{service}:*" not in not_actions:
                            full_access = True
                            break

    return full_access


def is_condition_restricting_from_private_ip(condition_statement: dict) -> bool:
    """Check if the policy condition is coming from a private IP address.

    Keyword arguments:
    condition_statement -- The policy condition to check. For example:
        {
            "IpAddress": {
                "aws:SourceIp": "X.X.X.X"
            }
        }
    """
    try:
        CONDITION_OPERATOR = "IpAddress"
        CONDITION_KEY = "aws:sourceip"

        is_from_private_ip = False

        if condition_statement.get(CONDITION_OPERATOR, {}):
            # We need to transform the condition_statement into lowercase
            condition_statement[CONDITION_OPERATOR] = {
                k.lower(): v for k, v in condition_statement[CONDITION_OPERATOR].items()
            }

            if condition_statement[CONDITION_OPERATOR].get(CONDITION_KEY, ""):
                if not isinstance(
                    condition_statement[CONDITION_OPERATOR][CONDITION_KEY], list
                ):
                    condition_statement[CONDITION_OPERATOR][CONDITION_KEY] = [
                        condition_statement[CONDITION_OPERATOR][CONDITION_KEY]
                    ]

                for ip in condition_statement[CONDITION_OPERATOR][CONDITION_KEY]:
                    # Select if IP address or IP network searching in the string for '/'
                    if "/" in ip:
                        if not ip_network(ip, strict=False).is_private:
                            break
                    else:
                        if not ip_address(ip).is_private:
                            break
                else:
                    is_from_private_ip = True

    except ValueError:
        logger.error(f"Invalid IP: {ip}")
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )

    return is_from_private_ip


def is_policy_public(policy: dict) -> bool:
    """
    Check if the statement allows public access to the resource or to a service principal.
    An AWS service principal is considered public access if the policy is not pair with conditions since it can be invoked by AWS services in other accounts.
    Args:
        policy (dict): The AWS policy to check
    Returns:
        bool: True if the policy allows public access, False otherwise
    """
    for statement in policy.get("Statement", []):
        # Only check allow statements
        if statement["Effect"] == "Allow":
            principal = statement.get("Principal", "")
            if (
                "*" in principal
                or "arn:aws:iam::*:root" in principal
                or (
                    isinstance(principal, dict)
                    and (
                        "*" in principal.get("AWS", "")
                        or "arn:aws:iam::*:root" in principal.get("AWS", "")
                        or (
                            isinstance(principal.get("AWS"), list)
                            and (
                                "*" in principal["AWS"]
                                or "arn:aws:iam::*:root" in principal["AWS"]
                            )
                        )
                        or "*" in principal.get("CanonicalUser", "")
                        or "arn:aws:iam::*:root" in principal.get("CanonicalUser", "")
                        or (  # Check if function can be invoked by other AWS services
                            (
                                ".amazonaws.com" in principal.get("Service", "")
                                or "*" in principal.get("Service", "")
                            )
                        )
                    )
                )
            ):
                return not has_secure_conditions(statement)
    return False


def has_secure_conditions(statement):
    """
    Check if the statement has secure conditions that restrict the access to the resource.
    Args:
        statement: dict: Statement from the policy
    Returns:
        bool: True if the statement has secure conditions, False otherwise
    """
    conditions = statement.get("Condition", {})
    allowed_conditions = {
        "aws:sourcearn",
        "aws:sourceip",
        "aws:sourcevpc",
        "aws:sourcevpce",
        "aws:sourceowner",
        "aws:sourceaccount",
        "aws:sourceorgid",
    }

    # Check for conditions with nested keys
    for _, conditions_dict in conditions.items():
        for key, value in conditions_dict.items():
            if isinstance(value, dict):
                if set(key.lower() for key in value.keys()).intersection(
                    allowed_conditions
                ):
                    return True
            elif key.lower() in allowed_conditions:
                return True
    return False
