def is_rule_allowing_permissions(rules, resources, verbs, api_groups=("",)):
    """
    Check whether any RBAC rule grants the specified verbs on the specified
    resources within the specified API groups.

    A rule matches when its `apiGroups` includes any of `api_groups` (or "*"),
    its `resources` includes any of `resources` (or "*"), and its `verbs`
    includes any of `verbs` (or "*").

    Args:
        rules (List[Rule]): RBAC rules from a Role or ClusterRole.
        resources (List[str]): Resources (or sub-resources) to check.
        verbs (List[str]): Verbs to check.
        api_groups (Iterable[str]): API groups the resources live in. Defaults
            to ("",), the core API group, which matches the most common case.
            Pass an explicit value for resources outside the core group, e.g.
            ("admissionregistration.k8s.io",) for webhook configurations.

    Returns:
        bool: True if any rule grants the permission, False otherwise.
    """
    if not rules:
        return False
    for rule in rules:
        if rule.apiGroups and not (
            any(g in rule.apiGroups for g in api_groups) or "*" in rule.apiGroups
        ):
            continue
        if (
            rule.resources
            and (any(r in rule.resources for r in resources) or "*" in rule.resources)
            and rule.verbs
            and (any(v in rule.verbs for v in verbs) or "*" in rule.verbs)
        ):
            return True
    return False
