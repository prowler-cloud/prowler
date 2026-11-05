from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.enclave import (
    attestation_condition_keys,
    is_enclave_key,
    statement_binds_deployment,
    statement_targets_sensitive_actions,
)


class kms_key_enclave_attestation_no_deployment_binding(Check):
    """Ensure enclave KMS attestation binds a specific deployment context.

    Deployment context per the AWS Nitro Enclaves docs. A sensitive Allow
    statement satisfies deployment binding when its Condition includes at
    least one of:

    - ``kms:RecipientAttestation:PCR3`` (IAM role of the parent instance) —
      AWS-recommended for portability,
    - ``kms:RecipientAttestation:PCR4`` (instance ID of the parent instance),
    - ``kms:RecipientAttestation:PCR8`` (EIF signing certificate) —
      AWS-recommended paired with PCR3, or
    - An account/org condition (``aws:PrincipalAccount``,
      ``aws:SourceAccount``, ``aws:PrincipalOrgID``, ``aws:ResourceAccount``,
      ``aws:PrincipalOrgPaths``) with a restrictive equality operator,
      **paired with** at least one restrictive RecipientAttestation binding.

    PCR0/PCR1/PCR2 all measure the enclave image (full EIF, kernel + boot
    ramfs, and user application respectively). They travel with the EIF, so
    a policy bound only to those PCRs still accepts the same image running
    in any account, on any instance. They do not bind a deployment context.

    Severity is INFORMATIONAL: this is a hardening recommendation, not a
    critical misconfiguration. Prowler models "informational findings" as
    ``status=FAIL`` with ``severity=informational``.

    - PASS: every sensitive Allow with attestation also binds deployment
      context.
    - FAIL (informational): at least one sensitive Allow with attestation
      lacks a deployment binding (PCR3/PCR4/PCR8/account condition).
    - MANUAL: the key has no sensitive Allow with attestation at all
      (handled by ``kms_key_enclave_attestation_not_enforced``; emitted with
      an honest message rather than a vacuous PASS).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the KMS enclave deployment-binding check.

        For each enclave-scoped customer-managed KMS key, collects every
        sensitive ``Allow`` statement that carries a restrictive
        ``kms:RecipientAttestation:*`` condition and verifies each one binds
        deployment context (PCR3/PCR4/PCR8 or account-level condition
        alongside the attestation binding). Emits MANUAL for keys without any
        sensitive Allow-with-attestation (covered by ``attestation_not_enforced``)
        and MANUAL for keys whose policy could not be fetched.

        Returns:
            list[Check_Report_AWS]: One report per selected enclave KMS key.
        """
        findings = []
        for key in kms_client.keys:
            if (
                key.manager != "CUSTOMER"
                or key.state != "Enabled"
                or not is_enclave_key(key)
            ):
                continue
            if key.policy is None:
                if getattr(key, "policy_fetch_error", None):
                    report = Check_Report_AWS(metadata=self.metadata(), resource=key)
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"KMS enclave key {key.id} policy could not be "
                        f"fetched ({key.policy_fetch_error}); deployment "
                        f"binding cannot be verified."
                    )
                    findings.append(report)
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=key)
            statements = key.policy.get("Statement") or []
            if isinstance(statements, dict):
                statements = [statements]

            attestation_stmts = [
                s
                for s in statements
                if isinstance(s, dict)
                and s.get("Effect") == "Allow"
                and statement_targets_sensitive_actions(s)
                and attestation_condition_keys(s)
            ]

            if not attestation_stmts:
                report.status = "MANUAL"
                report.status_extended = (
                    f"KMS enclave key {key.id} has no sensitive Allow "
                    f"statements with attestation conditions to evaluate; "
                    f"deployment-binding is not applicable. See "
                    f"kms_key_enclave_attestation_not_enforced."
                )
            else:
                missing = [
                    s.get("Sid", "<unnamed>")
                    for s in attestation_stmts
                    if not statement_binds_deployment(s)
                ]
                if not missing:
                    report.status = "PASS"
                    report.status_extended = (
                        f"KMS enclave key {key.id} binds attestation to a "
                        f"specific deployment context (PCR3, PCR4, PCR8, or "
                        f"account condition) on every sensitive statement."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"KMS enclave key {key.id} enforces attestation but "
                        f"statement(s) {missing} lack deployment-context "
                        f"binding (PCR3 role, PCR4 instance ID, PCR8 signing "
                        f"cert, or account-level condition). PCR0/PCR1/PCR2 "
                        f"identify the enclave image but travel with the EIF "
                        f"and do not bind where it runs."
                    )
            findings.append(report)
        return findings
