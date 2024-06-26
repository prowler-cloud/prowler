def is_rule_allowing_permisions(rules, resources, verbs):
    """
    Check Kubernetes role permissions.

    This function takes in Kubernetes role rules, resources, and verbs,
    and checks if any of the rules grant permissions on the specified
    resources with the specified verbs.

    Args:
        rules (List[Rule]): The list of Kubernetes role rules.
        resources (List[str]): The list of resources to check permissions for.
        verbs (List[str]): The list of verbs to check permissions for.

    Returns:
        bool: True if any of the rules grant permissions, False otherwise.
    """
    if rules:
        # Iterate through each rule in the list of rules
        for rule in rules:
            # Check if the rule has resources, verbs, and matches any of the specified resources and verbs
            if (
                rule.resources
                and (
                    any(resource in rule.resources for resource in resources)
                    or "*" in rule.resources
                )
                and rule.verbs
                and (any(verb in rule.verbs for verb in verbs) or "*" in rule.verbs)
            ):
                # If the rule matches, return True
                return True
    # If no rule matches, return False
    return False
