from py_iam_expand.actions import InvalidActionHandling, expand_actions

from prowler.lib.logger import logger

SENSITIVE_ENCLAVE_ACTIONS = {
    "kms:Decrypt",
    "kms:DeriveSharedSecret",
    "kms:GenerateDataKey",
    "kms:GenerateDataKeyPair",
    "kms:GenerateRandom",
}

ATTESTATION_CONDITION_PREFIX = "kms:RecipientAttestation:"
_ATTESTATION_PREFIX_LOWER = ATTESTATION_CONDITION_PREFIX.lower()


def _is_attestation_key(cond_key) -> bool:
    """AWS condition keys are case-insensitive, so match the prefix that way."""
    return isinstance(cond_key, str) and cond_key.lower().startswith(
        _ATTESTATION_PREFIX_LOWER
    )


def _expanded_actions(patterns) -> set:
    """Expand AWS action patterns (with wildcards) to canonical actions."""
    expanded = set()
    for pattern in patterns:
        try:
            expanded.update(
                expand_actions(pattern, InvalidActionHandling.REMOVE)
            )
        except Exception as error:
            # Do not crash the check on unrecognized patterns or library
            # errors, but leave an audit trail so silent failures can be
            # debugged in production.
            logger.error(
                f"expand_actions failed on pattern {pattern!r}: "
                f"{error.__class__.__name__}: {error}"
            )
    return expanded


def is_enclave_key(key) -> bool:
    """Return True when the KMS key looks like a Nitro Enclave workload key.

    Any signal suffices: tag ``prowler:enclave-key=true``, alias or
    description/tag containing ``enclave`` (case-insensitive), or a policy that
    already references any ``kms:RecipientAttestation:*`` condition key.
    """
    for t in key.tags or []:
        if (
            t.get("TagKey") == "prowler:enclave-key"
            and str(t.get("TagValue", "")).lower() == "true"
        ):
            return True

    for alias in getattr(key, "aliases", []) or []:
        if isinstance(alias, str) and "enclave" in alias.removeprefix("alias/").lower():
            return True

    description = getattr(key, "description", "") or ""
    if "enclave" in description.lower():
        return True
    for t in key.tags or []:
        if "enclave" in str(t.get("TagKey", "")).lower():
            return True
        if "enclave" in str(t.get("TagValue", "")).lower():
            return True

    if key.policy:
        statements = key.policy.get("Statement") or []
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements:
            if not isinstance(statement, dict):
                continue
            condition = statement.get("Condition") or {}
            for kv in condition.values():
                if isinstance(kv, dict) and any(
                    _is_attestation_key(k) for k in kv
                ):
                    return True

    return False


def statement_actions(statement) -> set:
    """Return the statement's Action field as a set (handles str or list)."""
    action = statement.get("Action", [])
    if isinstance(action, str):
        return {action}
    if isinstance(action, list):
        return {a for a in action if isinstance(a, str)}
    return set()


def statement_targets_sensitive_actions(statement) -> bool:
    """True when the statement grants any sensitive-enclave action.

    Uses py_iam_expand to canonicalize case and expand wildcards
    (``kms:GenerateDataKey*``, ``kms:*``, ``*``). ``NotAction`` in an Allow
    grants everything except the excluded set, so we return True unless the
    exclusion covers every sensitive action.
    """
    if "NotAction" in statement:
        raw = statement["NotAction"]
        if isinstance(raw, str):
            raw_patterns = {raw}
        elif isinstance(raw, list):
            raw_patterns = {p for p in raw if isinstance(p, str)}
        else:
            raw_patterns = set()
        excluded = _expanded_actions(raw_patterns)
        return not SENSITIVE_ENCLAVE_ACTIONS.issubset(excluded)

    patterns = statement_actions(statement)
    if not patterns:
        return False
    return bool(SENSITIVE_ENCLAVE_ACTIONS & _expanded_actions(patterns))


_RESTRICTIVE_ATTESTATION_OPERATORS = {
    "StringEquals",
    "StringEqualsIgnoreCase",
    "StringLike",
    "ForAllValues:StringEquals",
    "ForAllValues:StringEqualsIgnoreCase",
    "ForAllValues:StringLike",
    "ForAnyValue:StringEquals",
    "ForAnyValue:StringEqualsIgnoreCase",
    "ForAnyValue:StringLike",
}


def _values_are_restrictive(cond_value) -> bool:
    """A value (or value list) restricts access iff no entry contains a
    StringLike wildcard character (``*`` or ``?``). PCR and ImageSha
    attestation values are fixed hex hashes; any wildcard — full (``*``) or
    partial (``abc*``, ``abc??``) — makes the binding non-restrictive.
    """
    if isinstance(cond_value, str):
        return "*" not in cond_value and "?" not in cond_value
    if isinstance(cond_value, list):
        strings = [v for v in cond_value if isinstance(v, str)]
        return bool(strings) and all(
            "*" not in v and "?" not in v for v in strings
        )
    return False


def _null_guarded_keys(condition) -> set:
    """Return the (lowercased) condition keys guarded by ``Null: "false"``.

    A ``Null:false`` guard forces the request context key to be present, which
    blocks the vacuous-true evaluation of ``ForAllValues:*`` when the caller
    omits the key entirely.
    """
    guarded = set()
    null_block = condition.get("Null") or {}
    if not isinstance(null_block, dict):
        return guarded
    for key, value in null_block.items():
        if not isinstance(key, str):
            continue
        if isinstance(value, str) and value.lower() == "false":
            guarded.add(key.lower())
        elif isinstance(value, list) and any(
            isinstance(v, str) and v.lower() == "false" for v in value
        ):
            guarded.add(key.lower())
    return guarded


def attestation_condition_keys(statement) -> set:
    """Return the ``kms:RecipientAttestation:*`` keys bound by a restrictive condition.

    A binding counts only when the operator is in the restrictive whitelist
    (``StringEquals``, ``StringEqualsIgnoreCase``, ``StringLike`` and their
    ``ForAllValues:``/``ForAnyValue:`` variants) *and* the value is not the
    wildcard ``*``. Non-restrictive operators (``Null``, ``StringNotEquals``,
    ``StringNotLike``, ``*IfExists``) are ignored.

    ``ForAllValues:*`` variants evaluate to true when the request context key
    is absent, which lets a caller bypass attestation entirely. They only
    count as restrictive when the same statement pairs them with a
    ``Null:"false"`` guard on the same key.
    """
    keys = set()
    condition = statement.get("Condition", {}) or {}
    null_guarded = _null_guarded_keys(condition)
    for operator, kv in condition.items():
        if not isinstance(kv, dict):
            continue
        if operator not in _RESTRICTIVE_ATTESTATION_OPERATORS:
            continue
        is_for_all_values = operator.startswith("ForAllValues:")
        for cond_key, cond_value in kv.items():
            if not _is_attestation_key(cond_key):
                continue
            if not _values_are_restrictive(cond_value):
                continue
            if is_for_all_values and cond_key.lower() not in null_guarded:
                continue
            keys.add(cond_key)
    return keys


def collapse_pcr0_and_imagesha384(condition_keys) -> set:
    """Return the distinct attestation binding suffixes.

    ``ImageSha384`` is equivalent to ``PCR0`` per the RFC. Suffixes are
    normalized to upper case so different casings of the same PCR (e.g.,
    ``PCR0`` and ``pcr0``) collapse to one binding, matching AWS's
    case-insensitive condition-key semantics.
    """
    normalized = set()
    for key in condition_keys:
        suffix = key[len(ATTESTATION_CONDITION_PREFIX):]
        if suffix.lower() == "imagesha384":
            normalized.add("PCR0")
        else:
            normalized.add(suffix.upper())
    return normalized
