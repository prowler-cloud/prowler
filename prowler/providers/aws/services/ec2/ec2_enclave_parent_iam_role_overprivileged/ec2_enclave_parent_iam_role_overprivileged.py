from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.enclave import is_enclave_parent
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import (
    check_admin_access,
    check_full_service_access,
)


class ec2_enclave_parent_iam_role_overprivileged(Check):
    """Ensure Nitro Enclave parent IAM roles are not overprivileged.

    The IAM role attached through the parent's instance profile is the identity
    the enclave will operate under. Any wildcard grant of ``kms:*``,
    ``secretsmanager:*``, ``ssm:*`` or a full ``*:*`` administrator statement
    on ``Resource: "*"`` means a compromised parent can access every secret the
    enclave was designed to protect exclusively.

    - PASS: The parent has no instance profile, or every resolved role grants
      no wildcard access to the sensitive services on ``Resource: "*"``.
    - FAIL: A resolved role grants wildcard access to at least one sensitive
      service, or the instance profile cannot be resolved to any role
      (fail-closed: silent PASS on unresolved profiles would hide real risk).

    The instance profile is resolved via ``iam_client.instance_profiles``,
    which maps each profile ARN to the role names contained in it (populated
    from ``list_instance_profiles``). This handles the case where the profile
    name and the role name differ (common in Terraform/CloudFormation).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Nitro Enclave parent IAM overprivilege check.

        Resolves the IAM role behind each enclave-parent's instance profile,
        walks its attached managed policies and inline policies via
        ``iam_client.policies``, and uses the shared ``check_admin_access`` /
        ``check_full_service_access`` helpers to detect wildcard grants.

        Returns:
            list[Check_Report_AWS]: One report per enclave-enabled instance.
        """
        findings = []
        sensitive_services = ("kms", "secretsmanager", "ssm")

        for instance in ec2_client.instances:
            if not is_enclave_parent(instance):
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            profile = instance.instance_profile

            if not profile:
                report.status = "PASS"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} has no instance "
                    f"profile attached."
                )
                findings.append(report)
                continue

            profile_arn = profile.get("Arn", "")
            role_names = iam_client.instance_profiles.get(profile_arn, [])

            if not role_names:
                report.status = "FAIL"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} references instance "
                    f"profile '{profile_arn}' that could not be resolved to any IAM "
                    f"role; cannot verify least-privilege."
                )
                findings.append(report)
                continue

            matching_roles = [
                role for role in iam_client.roles or [] if role.name in role_names
            ]
            if not matching_roles:
                report.status = "FAIL"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} references instance "
                    f"profile '{profile_arn}' whose roles {sorted(role_names)} are "
                    f"not loaded in the IAM service; cannot verify least-privilege."
                )
                findings.append(report)
                continue

            overprivileged = set()
            offending_policies = []
            documents = []
            for matching_role in matching_roles:
                for attached in matching_role.attached_policies or []:
                    arn = attached.get("PolicyArn")
                    if arn and arn in iam_client.policies:
                        doc = iam_client.policies[arn].document
                        if doc:
                            documents.append(
                                (attached.get("PolicyName", arn), doc)
                            )
                for inline_name in matching_role.inline_policies or []:
                    inline_arn = f"{matching_role.arn}:policy/{inline_name}"
                    if inline_arn in iam_client.policies:
                        doc = iam_client.policies[inline_arn].document
                        if doc:
                            documents.append((inline_name, doc))

            for policy_name, document in documents:
                if check_admin_access(document):
                    overprivileged.add("*")
                    offending_policies.append(policy_name)
                    continue
                for service in sensitive_services:
                    if check_full_service_access(service, document):
                        overprivileged.add(f"{service}:*")
                        offending_policies.append(policy_name)

            role_labels = sorted({r.name for r in matching_roles})
            if overprivileged:
                report.status = "FAIL"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} uses role(s) "
                    f"{role_labels} with wildcard access to "
                    f"{sorted(overprivileged)} via {sorted(set(offending_policies))}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} role(s) "
                    f"{role_labels} do not grant wildcard access to "
                    f"{', '.join(sensitive_services)}."
                )
            findings.append(report)
        return findings
