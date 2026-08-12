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


def _role_is_privileged(role, policies) -> bool:
    """Return True when an IAM role grants administrative (``*:*``) access.

    Evaluates the AWS-managed AdministratorAccess policy by ARN, every attached
    managed policy document, and every inline policy document collected by the
    IAM service.

    Args:
        role: An ``iam_service.Role`` referenced by a Roles Anywhere profile.
        policies: Mapping of policy ARN to ``iam_service.Policy`` from iam_client.
    """
    for attached in role.attached_policies:
        policy_arn = attached.get("PolicyArn", "")
        if policy_arn.endswith(ADMIN_POLICY_ARN_SUFFIX):
            return True
        policy = policies.get(policy_arn)
        if _grants_full_access(getattr(policy, "document", None)):
            return True
    for inline_name in role.inline_policies:
        policy = policies.get(f"{role.arn}:policy/{inline_name}")
        if _grants_full_access(getattr(policy, "document", None)):
            return True
    return False


def _session_is_scoped(profile) -> bool:
    """Return True when the profile's session configuration restricts permissions.

    A session policy scopes the session unless it itself grants ``*:*``.
    Managed session policies scope the session unless one of them is the
    AWS-managed AdministratorAccess policy (the union would be unrestricted).

    Args:
        profile: A ``rolesanywhere_service.Profile``.
    """
    if profile.session_policy:
        try:
            document = json.loads(profile.session_policy)
        except (ValueError, TypeError):
            document = None
        if not _grants_full_access(document):
            return True
    if profile.managed_policy_arns and not any(
        arn.endswith(ADMIN_POLICY_ARN_SUFFIX) for arn in profile.managed_policy_arns
    ):
        return True
    return False


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
            elif _session_is_scoped(profile):
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
