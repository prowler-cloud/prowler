import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import check_full_service_access
from prowler.providers.aws.services.rolesanywhere.rolesanywhere_client import (
    rolesanywhere_client,
)

# AWS-managed AdministratorAccess ARN suffix, partition-agnostic
# (arn:aws:..., arn:aws-cn:..., arn:aws-us-gov:...).
ADMIN_POLICY_ARN_SUFFIX = ":iam::aws:policy/AdministratorAccess"

# Synthetic statement equivalent to the AWS-managed AdministratorAccess
# document, used when a policy is identified by that ARN but its document was
# not collected by the IAM service.
_ADMIN_STATEMENT = {"Effect": "Allow", "Action": "*", "Resource": "*"}


def _grants_full_access(document) -> bool:
    """Return True when a policy document grants administrative (``*:*``) access.

    Args:
        document: Decoded IAM policy document, or None when unavailable.
    """
    if not document:
        return False
    try:
        return check_full_service_access("*", document)
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False


def _unconditional_statements(documents) -> list:
    """Flatten policy documents into a single unconditional statement list.

    Statements guarded by a ``Condition`` cannot be evaluated statically: a
    conditional Allow does not prove access and a conditional Deny does not
    prove a restriction, so both are excluded from the merged evaluation.

    Args:
        documents: Iterable of decoded IAM policy documents.

    Returns:
        list: Every condition-free statement across the given documents.
    """
    statements = []
    for document in documents:
        if not document:
            continue
        document_statements = document.get("Statement", [])
        if not isinstance(document_statements, list):
            document_statements = [document_statements]
        statements.extend(
            statement
            for statement in document_statements
            if isinstance(statement, dict) and not statement.get("Condition")
        )
    return statements


def _role_is_privileged(role, policies) -> bool:
    """Return True when an IAM role effectively grants administrative access.

    Merges every attached and inline identity-policy document into a single
    statement set so an explicit deny in one policy negates an allow in another
    (Deny > Allow via the shared policy-evaluation helpers), excludes
    condition-guarded statements, and then intersects the result with the
    role's permissions boundary. A role whose boundary document cannot be
    resolved is classified as not administrative — restrictions that cannot be
    evaluated must not overstate effective access.

    Args:
        role: An ``iam_service.Role`` referenced by a Roles Anywhere profile.
        policies: Mapping of policy ARN to ``iam_service.Policy`` from iam_client.
    """
    documents = []
    for attached in role.attached_policies:
        policy_arn = attached.get("PolicyArn", "")
        policy = policies.get(policy_arn)
        document = getattr(policy, "document", None)
        if document:
            documents.append(document)
        elif policy_arn.endswith(ADMIN_POLICY_ARN_SUFFIX):
            documents.append({"Statement": [_ADMIN_STATEMENT]})
    for inline_name in role.inline_policies:
        policy = policies.get(f"{role.arn}:policy/{inline_name}")
        document = getattr(policy, "document", None)
        if document:
            documents.append(document)

    merged = {"Statement": _unconditional_statements(documents)}
    if not _grants_full_access(merged):
        return False

    # Effective permissions are the intersection of identity policies and the
    # permissions boundary: the role is administrative only when the boundary
    # also grants *:* (or there is no boundary).
    boundary = getattr(role, "permissions_boundary", None)
    if not boundary:
        return True
    boundary_arn = (
        boundary.get("PermissionsBoundaryArn", "") if isinstance(boundary, dict) else ""
    )
    if boundary_arn.endswith(ADMIN_POLICY_ARN_SUFFIX):
        return True
    boundary_document = getattr(policies.get(boundary_arn), "document", None)
    if not boundary_document:
        # Boundary restrictions cannot be evaluated: classify as unknown
        # rather than administrative.
        return False
    return _grants_full_access(
        {"Statement": _unconditional_statements([boundary_document])}
    )


def _session_is_scoped(profile, policies) -> bool:
    """Return True when the profile's session-policy set restricts permissions.

    AWS evaluates the inline ``sessionPolicy`` and every ``managedPolicyArns``
    entry together as a single session-policy category: an action allowed by any
    member is allowed by the session boundary. The session is therefore scoped
    only when at least one session policy exists and no member of the set grants
    ``*:*`` — a single administrative member (inline or managed) makes the whole
    boundary unrestricted regardless of how restrictive the others are. Managed
    entries are resolved through the collected IAM policies and their documents
    evaluated, so a customer-managed full-access policy is also unscoped; a
    managed policy whose document was not collected cannot be proven
    administrative and is treated as restrictive to avoid false positives.

    Args:
        profile: A ``rolesanywhere_service.Profile``.
        policies: Mapping of policy ARN to ``iam_service.Policy`` from iam_client.
    """
    if not profile.session_policy and not profile.managed_policy_arns:
        return False
    if profile.session_policy:
        try:
            document = json.loads(profile.session_policy)
        except (ValueError, TypeError):
            document = None
        if _grants_full_access(document):
            return False
    for arn in profile.managed_policy_arns or []:
        if arn.endswith(ADMIN_POLICY_ARN_SUFFIX):
            return False
        if _grants_full_access(getattr(policies.get(arn), "document", None)):
            return False
    return True


class rolesanywhere_profile_restricts_session_permissions(Check):
    """Flag Roles Anywhere profiles that vend an unscoped session on a privileged role.

    A Roles Anywhere profile that does not restrict the session with an inline
    ``sessionPolicy`` or ``managedPolicyArns`` vends temporary credentials
    carrying the full permissions of every role it references. This is only a
    real risk when a referenced role is itself administrative: any certificate
    accepted by the trust anchor then wields administrative permissions, turning
    the profile into a durable privileged-access path that surviving key rotation
    does not remove. Profiles that scope the session, whose referenced roles were
    not identified as administrative, or that are disabled are reported as PASS.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Evaluate session-permission scoping for Roles Anywhere profiles.

        Returns:
            list[Check_Report_AWS]: One report per Roles Anywhere profile. FAIL
            for enabled, unscoped profiles that reference an administrative role;
            PASS for scoped profiles, profiles whose roles were not identified as
            administrative, and disabled profiles.
        """
        findings = []
        roles_by_arn = {role.arn: role for role in iam_client.roles}
        for profile in rolesanywhere_client.profiles.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=profile)
            privileged_role_arns = [
                arn
                for arn in profile.role_arns
                if arn in roles_by_arn
                and _role_is_privileged(roles_by_arn[arn], iam_client.policies)
            ]
            if not profile.enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"IAM Roles Anywhere profile {profile.name} is disabled and "
                    "cannot vend session credentials."
                )
            elif _session_is_scoped(profile, iam_client.policies):
                report.status = "PASS"
                report.status_extended = (
                    f"IAM Roles Anywhere profile {profile.name} restricts vended "
                    "session permissions with a session policy or managed policies."
                )
            elif privileged_role_arns:
                report.status = "FAIL"
                report.status_extended = (
                    f"IAM Roles Anywhere profile {profile.name} does not scope down "
                    "sessions and references administrative role(s) "
                    f"{', '.join(privileged_role_arns)}; certificates authenticated "
                    "through it inherit administrative permissions, enabling durable "
                    "privileged access."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"IAM Roles Anywhere profile {profile.name} does not scope down "
                    "sessions, but no referenced role was identified as "
                    "administrative; scoping the session is recommended as "
                    "defense-in-depth."
                )
            findings.append(report)

        return findings
