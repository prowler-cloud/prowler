import base64
import binascii
import json
import re
from typing import Any

from py_iam_expand.actions import InvalidActionHandling, expand_actions

from prowler.lib.logger import logger

# CloudTrail event names that carry a Recipient attestation document when
# invoked by a Nitro Enclave. Kept in sync with ``SENSITIVE_ENCLAVE_ACTIONS``
# so the policy and runtime checks evaluate the same surface.
SENSITIVE_ENCLAVE_KMS_EVENTS = (
    "Decrypt",
    "DeriveSharedSecret",
    "GenerateDataKey",
    "GenerateDataKeyPair",
    "GenerateRandom",
)
DEFAULT_ENCLAVE_DEBUG_LOOKBACK_HOURS = (
    2160  # 90 days, matches CloudTrail management-event retention
)
DEFAULT_ENCLAVE_DEBUG_MAX_EVENTS = 5000
ENCLAVE_DEBUG_CONFIG_LOOKBACK_KEY = "enclave_debug_lookback_window_hours"
ENCLAVE_DEBUG_CONFIG_MAX_EVENTS_KEY = "enclave_debug_max_events"
ENCLAVE_DEBUG_CONFIG_TARGET_KEYS_KEY = "enclave_debug_target_key_ids"

DEFAULT_ENCLAVE_UNKNOWN_IMAGE_LOOKBACK_HOURS = (
    2160  # 90 days, matches CloudTrail management-event retention
)
DEFAULT_ENCLAVE_UNKNOWN_IMAGE_MAX_EVENTS = 5000
DEFAULT_ENCLAVE_UNKNOWN_IMAGE_SEVERITY = "medium"
ENCLAVE_UNKNOWN_IMAGE_CONFIG_LOOKBACK_KEY = (
    "enclave_unknown_image_lookback_window_hours"
)
ENCLAVE_UNKNOWN_IMAGE_CONFIG_MAX_EVENTS_KEY = "enclave_unknown_image_max_events"
ENCLAVE_UNKNOWN_IMAGE_CONFIG_TARGET_KEYS_KEY = "enclave_unknown_image_target_key_ids"
ENCLAVE_UNKNOWN_IMAGE_CONFIG_SEVERITY_KEY = "enclave_unknown_image_severity"
ENCLAVE_UNKNOWN_IMAGE_ALLOWED_SEVERITIES = ("medium", "high")

# Fields that debug mode zeros. Verified against AWS's official
# aws-nitro-enclaves-cli README: "All the platform configuration registers
# (PCRs) except for PCR3, PCR4 and PCR8 will have all their values set to 0".
# PCR0/1/2 are enclave measurements (image digest, kernel, application) —
# zeroed in debug mode. PCR3/4 encode host role and instance ID — always
# populated. PCR8 is the signing certificate — zeroed for unsigned EIFs
# regardless of debug mode.
_DEBUG_ZEROED_PCR_FIELDS = (
    "attestationDocumentEnclaveImageDigest",
    "attestationDocumentEnclavePCR1",
    "attestationDocumentEnclavePCR2",
)

# PCR values are SHA-384 hashes (48 bytes). They travel across the stack in two
# formats:
#   - **Hex** (96 chars): produced by ``nitro-cli describe-eif`` and typically
#     what users put in golden config and KMS policy conditions.
#   - **Base64** (64 chars): what CloudTrail records under
#     ``additionalEventData.recipient`` because JSON cannot carry raw bytes.
# All comparisons canonicalize to 48 raw bytes and are re-rendered as lower
# hex for storage/display.
_PCR_BYTE_LENGTH = 48
_PCR_HEX_RE = re.compile(r"^[0-9a-fA-F]{96}$")
_PCR_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{64}$")
_ALL_ZERO_PCR_BYTES = b"\x00" * _PCR_BYTE_LENGTH


def _pcr_to_bytes(value):
    """Return the 48-byte PCR value from hex (96 chars) or base64 (64 chars).

    Returns ``None`` when the input is not a string or cannot be decoded as
    either format. Accepts both because CloudTrail records base64 while
    ``nitro-cli`` and KMS policies use hex.
    """
    if not isinstance(value, str):
        return None
    if _PCR_HEX_RE.match(value):
        try:
            return bytes.fromhex(value)
        except ValueError:
            return None
    if _PCR_BASE64_RE.match(value):
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            return None
        if len(decoded) == _PCR_BYTE_LENGTH:
            return decoded
    return None


def _pcr_bytes_to_hex(pcr_bytes):
    """Canonical string form for storage / display."""
    return pcr_bytes.hex().lower()


def extract_pcrs_from_recipient(recipient: dict) -> dict:
    """Return ``{PCR_id: hex_value_lower}`` from a CloudTrail recipient block.

    ``ImageSha384`` (equivalent to PCR0 per the RFC) is collapsed under
    ``PCR0``. Values are canonicalized to **lowercase hex** regardless of
    the wire format (CloudTrail emits base64, some sources use hex). Non-
    string, non-decodable, or absent PCR fields are skipped so partial /
    truncated recipients yield partial maps rather than raising.
    """
    if not isinstance(recipient, dict):
        return {}
    per_pcr: dict = {}
    field_to_pcr = {
        "attestationDocumentEnclaveImageDigest": "PCR0",
        "attestationDocumentEnclavePCR1": "PCR1",
        "attestationDocumentEnclavePCR2": "PCR2",
        "attestationDocumentEnclavePCR3": "PCR3",
        "attestationDocumentEnclavePCR4": "PCR4",
        "attestationDocumentEnclavePCR8": "PCR8",
    }
    for field, pcr_id in field_to_pcr.items():
        raw = recipient.get(field)
        pcr_bytes = _pcr_to_bytes(raw)
        if pcr_bytes is not None:
            per_pcr[pcr_id] = _pcr_bytes_to_hex(pcr_bytes)
    return per_pcr


def is_debug_attestation(recipient: dict) -> bool:
    """Return True when a CloudTrail attestation recipient looks debug-mode.

    Reality vs docs: the RFC v2.6 and the AWS user guide describe debug mode
    as "all PCRs zeroed", but the aws-nitro-enclaves-cli README (and empirical
    playground behavior) confirm that only the **enclave-measurement** PCRs
    are zeroed — PCR3/PCR4 encode host role/instance and are always populated,
    PCR8 depends on EIF signing.

    A recipient is classified as debug-mode when every field in
    ``_DEBUG_ZEROED_PCR_FIELDS`` (PCR0 = ImageDigest, PCR1, PCR2) is present
    AND decodes to 48 all-zero bytes. Values may arrive in either hex
    (nitro-cli/audit_config format) or base64 (CloudTrail format); both are
    normalized transparently. Partial recipients (missing any of the three
    diagnostic fields) or non-decodable values are conservative-False.
    """
    if not isinstance(recipient, dict):
        return False
    for key in _DEBUG_ZEROED_PCR_FIELDS:
        raw = recipient.get(key)
        pcr_bytes = _pcr_to_bytes(raw)
        if pcr_bytes is None or pcr_bytes != _ALL_ZERO_PCR_BYTES:
            return False
    return True


def _extract_key_arn(raw, event):
    """Return the KMS key ARN referenced by a CloudTrail event, or ``None``.

    The ARN can appear in the top-level ``Resources`` block (as returned by
    ``lookup_events``) or inside the ``resources`` field of the parsed
    payload. Both are tolerated to guard against schema drift.
    """
    for source in (raw.get("Resources") or [], event.get("resources") or []):
        for res in source:
            if not isinstance(res, dict):
                continue
            rtype = res.get("ResourceType") or res.get("type") or ""
            if isinstance(rtype, str) and "KMS::Key" in rtype:
                arn = res.get("ResourceName") or res.get("ARN")
                if isinstance(arn, str) and arn.startswith("arn:"):
                    return arn
    return None


def parse_enclave_kms_event(raw: dict) -> dict | None:
    """Return a parsed enclave-KMS event or ``None`` when non-relevant.

    ``raw`` is a single CloudTrail Event as returned by ``lookup_events``: a
    dict with a ``CloudTrailEvent`` JSON-string payload. Returns ``None`` for
    events without the enclave recipient block, unrecognized module IDs, or
    malformed JSON. When relevant, returns a dict with ``instance_id``,
    ``event_time``, ``event_name``, ``is_debug`` and ``key_arn`` (the latter
    may be ``None`` if the event's Resources block does not name a key).
    """
    payload = raw.get("CloudTrailEvent")
    if not isinstance(payload, str):
        return None
    try:
        event = json.loads(payload)
    except (ValueError, TypeError):
        return None
    additional = event.get("additionalEventData")
    recipient = additional.get("recipient") if isinstance(additional, dict) else None
    if not isinstance(recipient, dict):
        return None
    module_id = recipient.get("attestationDocumentModuleId")
    if not isinstance(module_id, str) or "-enc" not in module_id:
        return None
    return {
        "instance_id": module_id.split("-enc", 1)[0],
        "event_time": raw.get("EventTime") or event.get("eventTime"),
        "event_name": event.get("eventName"),
        "is_debug": is_debug_attestation(recipient),
        "key_arn": _extract_key_arn(raw, event),
        "observed_pcrs": extract_pcrs_from_recipient(recipient),
    }


def unknown_pcrs(observed: dict, golden: dict) -> dict:
    """Return observed PCRs not present in the golden list for their bucket.

    Semantics: only PCR IDs that have a golden list configured are evaluated.
    Observed PCR buckets without a golden baseline are NOT flagged — without
    a baseline we cannot make an "unknown" assertion. Operators who want to
    catch unknown values in a specific PCR bucket must add a golden list for
    that bucket in ``audit_config``. This matches the semantics documented
    in the ``kms_key_enclave_attestation_unknown_image`` metadata Notes.

    Values are compared as raw bytes: the observed value comes from CloudTrail
    (typically base64) and the golden values come from ``audit_config`` (users
    typically paste hex from ``nitro-cli describe-eif``). Both are decoded to
    48-byte SHA384 buffers before comparison so hex/base64 mismatches don't
    cause false positives.
    """
    if not isinstance(observed, dict) or not isinstance(golden, dict):
        return {}
    unknown = {}
    for pcr_id, value in observed.items():
        allowed = golden.get(pcr_id)
        if not allowed:
            continue
        obs_bytes = _pcr_to_bytes(value)
        if obs_bytes is None:
            continue
        allowed_bytes = {b for a in allowed if (b := _pcr_to_bytes(a)) is not None}
        if obs_bytes not in allowed_bytes:
            unknown[pcr_id] = value
    return unknown


def key_id_from_arn(arn: str) -> str:
    """Return the KMS key-id suffix of a full ARN, or the input verbatim.

    Accepts both aliases (``arn:aws:kms:*:*:key/<uuid>``) and non-KMS or
    malformed strings; in the latter case returns the input unchanged so
    callers can compare against opaque identifiers without special-casing.
    """
    if not isinstance(arn, str) or "/" not in arn:
        return arn or ""
    return arn.rsplit("/", 1)[-1]


def resolve_kms_key_resource(kms_client_ref, arn):
    """Return the Key model matching ``arn`` or a lightweight stub.

    When a CloudTrail event references a key that is not in ``kms_client``
    (different region, KMS-key-not-in-cache, etc.), we still need a resource
    object with ``arn``, ``id`` and ``region`` for ``Check_Report_AWS`` to
    populate its resource fields. The stub carries the ARN as identity so
    the report stays actionable.
    """
    for key in kms_client_ref.keys:
        if key.arn == arn:
            return key
    return _StubKmsResource(arn=arn, region=getattr(kms_client_ref, "region", "global"))


def synthetic_account_kms_resource(account_id, region):
    """Return a placeholder resource for account-scoped findings.

    Used when the check has nothing key-specific to report (e.g., no
    CloudTrail trails at all) but must still emit a finding.
    """
    return _StubKmsResource(
        arn=f"arn:aws:kms:{region or 'global'}:{account_id or 'unknown'}:enclave-debug-attestation",
        region=region or "global",
    )


class _StubKmsResource:
    """Minimal resource shim for ``Check_Report_AWS`` when the Key is out of cache.

    ``Check_Report`` calls ``.dict()`` on the resource to serialize into the
    finding's ``resource`` field. Without this, Prowler logs a "could not be
    converted to dict" ERROR and drops the resource metadata (leaving
    ``resource_id/arn/region`` populated via getattr but ``resource`` empty).
    """

    def __init__(self, arn: str, region: str):
        self.arn = arn
        self.id = key_id_from_arn(arn) or arn
        self.region = region
        self.tags = []

    def dict(self):
        return {
            "arn": self.arn,
            "id": self.id,
            "region": self.region,
            "tags": self.tags,
        }


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
            expanded.update(expand_actions(pattern, InvalidActionHandling.REMOVE))
        except Exception as error:
            # Do not crash the check on unrecognized patterns or library
            # errors, but leave an audit trail so silent failures can be
            # debugged in production.
            logger.error(
                f"expand_actions failed on pattern {pattern!r}: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: "
                f"{error}"
            )
    return expanded


def is_enclave_key(key: Any) -> bool:
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
                if isinstance(kv, dict) and any(_is_attestation_key(k) for k in kv):
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


def _sensitive_actions_granted(statement) -> set:
    """Return the sensitive-enclave actions this Allow statement effectively grants."""
    if "NotAction" in statement:
        raw = statement["NotAction"]
        if isinstance(raw, str):
            raw_patterns = {raw}
        elif isinstance(raw, list):
            raw_patterns = {p for p in raw if isinstance(p, str)}
        else:
            raw_patterns = set()
        excluded = _expanded_actions(raw_patterns)
        return SENSITIVE_ENCLAVE_ACTIONS - excluded
    return SENSITIVE_ENCLAVE_ACTIONS & _expanded_actions(statement_actions(statement))


def _deny_covers_missing_attestation(deny_stmt, sensitive_actions) -> bool:
    """Return True when a Deny fires whenever attestation context is absent.

    Recognized patterns:

    - ``Null: {"kms:RecipientAttestation:PCR*": "true"}`` — Deny when the
      attestation context key is absent from the request.
    - ``StringNotEqualsIfExists`` / ``StringNotEqualsIgnoreCaseIfExists``
      over ``kms:RecipientAttestation:*`` — the ``IfExists`` variant treats
      absent keys as matching the operator, so combined with Deny it also
      denies calls without attestation.

    The Deny also has to cover every sensitive action the Allow granted; a
    Deny that only names ``kms:Decrypt`` does not neutralize an Allow that
    granted ``kms:GenerateDataKey`` too.
    """
    if not isinstance(deny_stmt, dict) or deny_stmt.get("Effect") != "Deny":
        return False
    principal = deny_stmt.get("Principal")
    # Accept every AWS-idiomatic way of writing "everyone":
    #   - ``"*"``
    #   - ``{"AWS": "*"}``
    #   - ``{"AWS": ["*"]}``  (list form is a legitimate policy variant)
    # NotPrincipal is intentionally NOT evaluated here.
    is_everyone = principal == "*" or (
        isinstance(principal, dict)
        and (
            principal.get("AWS") == "*"
            or (isinstance(principal.get("AWS"), list) and "*" in principal["AWS"])
        )
    )
    if not is_everyone:
        return False
    # A Deny with NotAction denies everything except the listed set. It
    # covers the sensitive Allow when the NotAction list does NOT include
    # any of the sensitive actions the Allow granted.
    if "NotAction" in deny_stmt:
        raw = deny_stmt["NotAction"]
        if isinstance(raw, str):
            raw_patterns = {raw}
        elif isinstance(raw, list):
            raw_patterns = {p for p in raw if isinstance(p, str)}
        else:
            raw_patterns = set()
        excluded = _expanded_actions(raw_patterns)
        if not sensitive_actions.isdisjoint(excluded):
            # At least one sensitive action is in the NotAction exclusion set →
            # this Deny does NOT deny that action, so it cannot cover the
            # bypass on that action.
            return False
    else:
        deny_actions = _expanded_actions(statement_actions(deny_stmt))
        if not sensitive_actions.issubset(deny_actions):
            return False
    condition = deny_stmt.get("Condition") or {}
    if not isinstance(condition, dict):
        return False
    null_block = condition.get("Null") or {}
    if isinstance(null_block, dict):
        for k, v in null_block.items():
            if not isinstance(k, str) or not _is_attestation_key(k):
                continue
            if isinstance(v, str) and v.lower() == "true":
                return True
            if isinstance(v, list) and any(
                isinstance(x, str) and x.lower() == "true" for x in v
            ):
                return True
    for op in ("StringNotEqualsIfExists", "StringNotEqualsIgnoreCaseIfExists"):
        block = condition.get(op) or {}
        if isinstance(block, dict) and any(
            isinstance(k, str) and _is_attestation_key(k) for k in block
        ):
            return True
    return False


def statement_is_covered_by_deny(allow_stmt, policy) -> bool:
    """Return True when an unconditioned Allow is neutralized by a Deny.

    Iterates the policy's Deny statements looking for one that fires when
    the caller does not present a valid ``kms:RecipientAttestation:*``
    context key AND that covers every sensitive action the Allow granted.
    """
    sensitive = _sensitive_actions_granted(allow_stmt)
    if not sensitive:
        return True
    statements = policy.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if _deny_covers_missing_attestation(stmt, sensitive):
            return True
    return False


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
        return bool(strings) and all("*" not in v and "?" not in v for v in strings)
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


def _normalize_pcr_suffix(cond_key) -> str:
    """Return the upper-cased suffix, mapping ``ImageSha384`` to ``PCR0``.

    ``ImageSha384`` is equivalent to ``PCR0`` per the RFC. Casings collapse via
    upper-case to match AWS's case-insensitive condition-key semantics.
    """
    suffix = cond_key[len(ATTESTATION_CONDITION_PREFIX) :]
    if suffix.lower() == "imagesha384":
        return "PCR0"
    return suffix.upper()


def collapse_pcr0_and_imagesha384(condition_keys) -> set:
    """Return the distinct attestation binding suffixes.

    Delegates each key to ``_normalize_pcr_suffix`` so ``ImageSha384`` and
    every casing of ``PCR0`` collapse to a single ``PCR0`` binding.
    """
    return {_normalize_pcr_suffix(key) for key in condition_keys}


# Deployment-context binding per AWS Nitro Enclaves docs
# (https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#where):
#   * PCR3 = IAM role of the parent instance (AWS-recommended binding)
#   * PCR4 = Instance ID of the parent instance
#   * PCR8 = EIF signing certificate
# AWS explicitly recommends "PCR3 and PCR8 together for the best flexibility".
#
# PCR1 (kernel + boot ramfs) and PCR2 (application) are intentionally NOT
# accepted: they are image-identity refinements that travel with the EIF,
# just like PCR0. A key bound only to PCR0+PCR1+PCR2 still accepts the same
# EIF running anywhere. This diverges from RFC v2.7 §6 Check 8's summary
# table (which lists PCR1/PCR2) because the check's semantic contract is
# "no_deployment_binding" — accepting software-identity PCRs would mislabel
# image-identity bindings as deployment bindings.
_DEPLOYMENT_PCR_SUFFIXES = {"PCR3", "PCR4", "PCR8"}
_DEPLOYMENT_ACCOUNT_CONDITION_KEYS = {
    "aws:principalaccount",
    "aws:sourceaccount",
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:resourceaccount",
}
# Strictly restrictive equality operators only. Deliberately excludes:
#   * StringEqualsIfExists / StringEqualsIgnoreCaseIfExists — vacuous-true
#     when the request-context key is absent (same trap as ForAllValues without
#     a Null:false guard); would allow bypass by omitting the key.
#   * ArnLike — accepts wildcards ``*``/``?`` in the value; does not bind to a
#     specific ARN by definition.
#   * ForAllValues:* — vacuous-true when the key is absent.
#   * ForAnyValue:* — matches if ANY value in a multi-valued context matches,
#     not restrictive for multi-valued keys.
_DEPLOYMENT_ACCOUNT_OPERATORS = {
    "StringEquals",
    "StringEqualsIgnoreCase",
    "ArnEquals",
}


def statement_binds_deployment(statement) -> bool:
    """Return True when a sensitive Allow's Condition binds deployment context.

    Deployment context per AWS Nitro Enclaves docs = any of:
      - PCR3 (IAM role of the parent instance) as a restrictive attestation
        binding — AWS-recommended for portability, OR
      - PCR4 (instance ID of the parent instance) as a restrictive
        attestation binding, OR
      - PCR8 (EIF signing certificate) as a restrictive attestation
        binding — AWS-recommended paired with PCR3, OR
      - An account-level condition (``aws:PrincipalAccount``,
        ``aws:SourceAccount``, ``aws:PrincipalOrgID``, ``aws:ResourceAccount``,
        ``aws:PrincipalOrgPaths``) with a **strictly restrictive** equality
        operator (``StringEquals``, ``StringEqualsIgnoreCase``, ``ArnEquals``)
        AND a non-wildcard value, paired with at least one restrictive
        RecipientAttestation binding.

    Non-restrictive operator families are intentionally rejected: ``*IfExists``
    (vacuous-true when the request-context key is absent), ``ArnLike`` (allows
    wildcards), ``ForAllValues:*`` (vacuous-true when the key is absent), and
    ``ForAnyValue:*`` (matches partial multi-value contexts). Using any of
    these does NOT satisfy deployment binding for this check.

    PCR0/PCR1/PCR2 identify the enclave image (whole EIF / kernel / app) but
    all travel with the EIF and do not tighten where the image is allowed to
    run. A policy bound only to those PCRs returns False here and the check
    emits FAIL (severity: informational).
    """
    condition = statement.get("Condition") or {}
    if not isinstance(condition, dict):
        return False
    attestation_keys = attestation_condition_keys(statement)
    if not attestation_keys:
        return False
    bindings = collapse_pcr0_and_imagesha384(attestation_keys)
    if bindings & _DEPLOYMENT_PCR_SUFFIXES:
        return True
    for op, block in condition.items():
        if op not in _DEPLOYMENT_ACCOUNT_OPERATORS or not isinstance(block, dict):
            continue
        for cond_key, cond_value in block.items():
            if not isinstance(cond_key, str):
                continue
            if cond_key.lower() not in _DEPLOYMENT_ACCOUNT_CONDITION_KEYS:
                continue
            if _values_are_restrictive(cond_value):
                return True
    return False


GOLDEN_PCR_CONFIG_KEY = "enclave_golden_pcr_values"


def normalize_golden_pcr_config(raw) -> dict:
    """Normalize the ``audit_config`` golden-PCR block to ``{PCR_id: {values}}``.

    Accepts the raw ``{PCR0: [hash, ...], ...}`` shape from ``audit_config``.
    Non-string PCR IDs and non-list value collections are dropped. Values are
    lower-cased so they compare deterministically against the values returned
    by ``attestation_values_by_pcr``. PCR buckets with no usable values are
    omitted so callers can treat their presence as "configured".
    """
    if not isinstance(raw, dict):
        return {}
    normalized: dict = {}
    for pcr_id, values in raw.items():
        if not isinstance(pcr_id, str):
            continue
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list):
            continue
        cleaned = {v.lower() for v in values if isinstance(v, str) and v}
        if not cleaned:
            continue
        normalized[pcr_id.upper()] = cleaned
    return normalized


def attestation_values_by_pcr(statement) -> dict:
    """Return a ``{PCR_id: {values}}`` map of restrictive attestation bindings.

    Only condition keys returned by ``attestation_condition_keys`` (i.e., those
    already filtered for restrictive operators, non-wildcard values, and
    ``ForAllValues:`` + ``Null:false`` pairing) contribute. Values are
    lower-cased so hex hashes compare deterministically against the configured
    golden list. ``ImageSha384`` values collapse under the ``PCR0`` bucket to
    match ``collapse_pcr0_and_imagesha384``'s semantics.
    """
    per_pcr: dict = {}
    restrictive_keys = attestation_condition_keys(statement)
    if not restrictive_keys:
        return per_pcr
    restrictive_lower = {k.lower() for k in restrictive_keys}
    condition = statement.get("Condition", {}) or {}
    for operator, kv in condition.items():
        if not isinstance(kv, dict):
            continue
        if operator not in _RESTRICTIVE_ATTESTATION_OPERATORS:
            continue
        for cond_key, cond_value in kv.items():
            if not isinstance(cond_key, str):
                continue
            if cond_key.lower() not in restrictive_lower:
                continue
            pcr_id = _normalize_pcr_suffix(cond_key)
            if isinstance(cond_value, str):
                values = [cond_value]
            elif isinstance(cond_value, list):
                values = [v for v in cond_value if isinstance(v, str)]
            else:
                continue
            bucket = per_pcr.setdefault(pcr_id, set())
            for v in values:
                bucket.add(v.lower())
    return per_pcr
