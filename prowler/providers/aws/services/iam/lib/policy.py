from ipaddress import ip_address, ip_network

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import read_aws_regions_file


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


def process_actions(effect, actions, target_set):
    """
    process_actions processes the actions in the policy.
    Args:
        effect (str): The effect of the policy.
        actions (str or list): The actions to process.
        target_set (set): The set to store the actions.
    """
    if effect in ["Allow", "Deny"] and actions:
        if isinstance(actions, str):
            target_set.add(actions)
        elif isinstance(actions, list):
            target_set.update(actions)


def check_admin_access(policy: dict) -> bool:
    """
    check_admin_access checks if the policy allows admin access.
    Args:
        policy (dict): The policy to check.
    Returns:
        bool: True if the policy allows admin access, False otherwise.
    """

    if policy:
        allowed_actions = set()
        allowed_not_actions = set()
        denied_actions = set()
        denied_not_actions = set()

        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            if statement.get("Resource") in [
                "*",
                ["*"],
                ["*/*"],
                "*/*",
                ["*:*"],
                "*:*",
            ] or (
                statement.get("NotResource")
                and statement.get("NotResource") not in ["*", ["*"]]
            ):
                effect = statement.get("Effect")
                actions = statement.get("Action")
                not_actions = statement.get("NotAction")
                if effect == "Allow":
                    process_actions(effect, actions, allowed_actions)
                    process_actions(effect, not_actions, allowed_not_actions)
                elif effect == "Deny":
                    process_actions(effect, actions, denied_actions)
                    process_actions(effect, not_actions, denied_not_actions)

        # If there is only NotAction, it allows the rest of the actions
        if not allowed_actions and allowed_not_actions:
            allowed_actions.add("*")
        # Check for invalid services in allowed NotAction
        if allowed_not_actions:
            invalid_not_actions = check_invalid_not_actions(allowed_not_actions)
            if invalid_not_actions:
                # Since it is an invalid NotAction, it allows all AWS actions
                allowed_actions.add("*")

        if "*" in allowed_actions:
            return True
        return False


def check_invalid_not_actions(not_actions):
    """
    Checks if the actions in NotAction have services that are not part of AWS.
    Args:
        not_actions (str or list): The NotAction to check.
    Returns:
        dict: A dictionary with invalid services and their actions.
    """
    invalid_services = {}

    if isinstance(not_actions, str):
        not_actions = [not_actions]

    for action in not_actions:
        service = action.split(":")[0]
        if not is_valid_aws_service(service):
            if service not in invalid_services:
                invalid_services[service] = []
            invalid_services[service].append(action)

    return invalid_services


def is_valid_aws_service(service):
    """
    Checks if a service is a valid AWS service using aws_regions_by_service.json.
    Args:
        service (str): The service to check.
    Returns:
        bool: True if the service is valid, False otherwise.
    """
    if service in read_aws_regions_file()["services"]:
        return True
    return False
