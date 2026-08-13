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


def _full_access_status(documents) -> bool | None:
    """Return whether a policy-document set grants ``*:*``, or None when unknown.

    Merges every condition-free statement across the given documents into a
    single evaluation so an explicit deny in one document negates an allow in
    another (Deny > Allow via the shared policy-evaluation helpers).

    Unresolved or malformed documents and context-dependent semantics cannot
    produce a definitive classification and propagate as None:

    - a document that is missing or not a well-formed statement container;
    - a ``Condition``-guarded Deny that could negate an otherwise proven
      full-access grant;
    - a ``Condition``-guarded Allow that could grant full access not proven
      by the unconditional statements.

    Args:
        documents: Iterable of decoded IAM policy documents (None members mark
            documents that could not be resolved).
    """
    statements = []
    conditional_effects = set()

    for document in documents:
        if not isinstance(document, dict) or "Statement" not in document:
            return None

        document_statements = document.get("Statement", [])
        if not isinstance(document_statements, list):
            document_statements = [document_statements]

        for statement in document_statements:
            if not isinstance(statement, dict):
                return None

            effect = str(statement.get("Effect", "")).lower()
            if (
                effect not in {"allow", "deny"}
                or not ("Action" in statement or "NotAction" in statement)
                or not ("Resource" in statement or "NotResource" in statement)
            ):
                return None

            if statement.get("Condition"):
                conditional_effects.add(effect)
            else:
                statements.append(statement)

    grants_full_access = _grants_full_access({"Statement": statements})
    if (grants_full_access and "deny" in conditional_effects) or (
        not grants_full_access and "allow" in conditional_effects
    ):
        return None

    return grants_full_access


def _role_is_privileged(role, policies) -> bool | None:
    """Return whether an IAM role is administrative, or None when unknown.

    Effective permissions are the intersection of the role's identity policies
    (attached and inline, evaluated together) and its permissions boundary.
    Unresolved policy documents, malformed policies, and condition-guarded
    statements that could change the outcome propagate as None instead of
    being collapsed into a definitive classification.

    Args:
        role: An ``iam_service.Role`` referenced by a Roles Anywhere profile.
        policies: Mapping of policy ARN to ``iam_service.Policy`` from iam_client.
    """
    documents = []
    for attached in role.attached_policies:
        policy_arn = attached.get("PolicyArn", "")
        document = getattr(policies.get(policy_arn), "document", None)
        if policy_arn.endswith(ADMIN_POLICY_ARN_SUFFIX) and not document:
            documents.append({"Statement": [_ADMIN_STATEMENT]})
        else:
            documents.append(document)
    for inline_name in role.inline_policies:
        policy = policies.get(f"{role.arn}:policy/{inline_name}")
        documents.append(getattr(policy, "document", None))

    identity_status = _full_access_status(documents)
    if identity_status is False:
        # Identity policies provably do not grant *:*; no boundary can widen them.
        return False

    boundary = getattr(role, "permissions_boundary", None)
    if not boundary:
        return identity_status
    boundary_arn = (
        boundary.get("PermissionsBoundaryArn", "") if isinstance(boundary, dict) else ""
    )
    if boundary_arn.endswith(ADMIN_POLICY_ARN_SUFFIX):
        # An AdministratorAccess boundary restricts nothing.
        return identity_status

    boundary_status = _full_access_status(
        [getattr(policies.get(boundary_arn), "document", None)]
    )
    if boundary_status is False:
        # The boundary provably does not grant *:*: the intersection cannot be
        # administrative regardless of the identity policies.
        return False
    if boundary_status is None:
        return None
    return identity_status


def _session_is_scoped(profile, policies) -> bool | None:
    """Return whether session policies restrict permissions, or None when unknown.

    AWS evaluates the inline ``sessionPolicy`` and every ``managedPolicyArns``
    entry together as a single session-policy category, so the complete set is
    merged into one evaluation: the session is scoped only when at least one
    session policy exists and the set does not grant ``*:*``. Managed entries
    are resolved through the collected IAM policies. An invalid inline policy
    or an unresolved managed policy does not prove that the session is
    restricted and propagates as None.

    Args:
        profile: A ``rolesanywhere_service.Profile``.
        policies: Mapping of policy ARN to ``iam_service.Policy`` from iam_client.
    """
    if not profile.session_policy and not profile.managed_policy_arns:
        return False

    documents = []
    if profile.session_policy:
        try:
            documents.append(json.loads(profile.session_policy))
        except (ValueError, TypeError):
            return None
    for arn in profile.managed_policy_arns or []:
        if arn.endswith(ADMIN_POLICY_ARN_SUFFIX):
            documents.append({"Statement": [_ADMIN_STATEMENT]})
        else:
            documents.append(getattr(policies.get(arn), "document", None))

    grants_full_access = _full_access_status(documents)
    return None if grants_full_access is None else not grants_full_access


class rolesanywhere_profile_restricts_session_permissions(Check):
    """Flag Roles Anywhere profiles that vend an unscoped session on a privileged role.

    A Roles Anywhere profile that does not restrict the session with an inline
    ``sessionPolicy`` or ``managedPolicyArns`` vends temporary credentials
    carrying the full permissions of every role it references. This is only a
    real risk when a referenced role is itself administrative: any certificate
    accepted by the trust anchor then wields administrative permissions, turning
    the profile into a durable privileged-access path that surviving key rotation
    does not remove. Profiles that scope the session, whose referenced roles were
    proven not administrative, or that are disabled are reported as PASS. When
    session scoping or role permissions cannot be evaluated (unresolved or
    invalid policy documents, condition-guarded grants, unknown roles), the
    report is MANUAL rather than a proven outcome.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Evaluate session-permission scoping for Roles Anywhere profiles.

        Returns:
            list[Check_Report_AWS]: One report per Roles Anywhere profile. FAIL
            for enabled, unscoped profiles that reference a proven administrative
            role; MANUAL when session scoping or role permissions could not be
            evaluated; PASS for scoped profiles, profiles whose roles were proven
            not administrative, and disabled profiles.
        """
        findings = []
        roles_by_arn = {role.arn: role for role in iam_client.roles}
        for profile in rolesanywhere_client.profiles.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=profile)
            role_statuses = {
                arn: (
                    _role_is_privileged(roles_by_arn[arn], iam_client.policies)
                    if arn in roles_by_arn
                    else None
                )
                for arn in profile.role_arns
            }
            privileged_role_arns = [
                arn for arn, status in role_statuses.items() if status is True
            ]
            unknown_role_arns = [
                arn for arn, status in role_statuses.items() if status is None
            ]
            session_scoped = _session_is_scoped(profile, iam_client.policies)

            if not profile.enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"IAM Roles Anywhere profile {profile.name} is disabled and "
                    "cannot vend session credentials."
                )
            elif session_scoped is True:
                report.status = "PASS"
                report.status_extended = (
                    f"IAM Roles Anywhere profile {profile.name} restricts vended "
                    "session permissions with a session policy or managed policies."
                )
            elif session_scoped is None:
                report.status = "MANUAL"
                report.status_extended = (
                    f"IAM Roles Anywhere profile {profile.name} session scoping "
                    "could not be evaluated because an inline or managed session "
                    "policy was invalid or unresolved."
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
            elif unknown_role_arns:
                report.status = "MANUAL"
                report.status_extended = (
                    f"IAM Roles Anywhere profile {profile.name} does not scope down "
                    "sessions, and the effective permissions of referenced role(s) "
                    f"{', '.join(unknown_role_arns)} could not be evaluated."
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
