from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.enclave import (
    attestation_condition_keys,
    collapse_pcr0_and_imagesha384,
    is_enclave_key,
    statement_targets_sensitive_actions,
)


class kms_key_enclave_pcr_too_broad(Check):
    """Ensure enclave KMS attestation binds at least two distinct PCR values.

    ``kms:RecipientAttestation:PCR0`` alone (the enclave image hash) can be
    satisfied by any enclave built from the same EIF. Adding a second binding
    (``PCR1`` for kernel/bootstrap, ``PCR2`` for application, ``PCR8`` for the
    signing certificate, ``ImageSha384`` for the raw image hash, or a custom
    PCR ID) provides defense-in-depth. Because ``ImageSha384`` is equivalent
    to ``PCR0``, the two collapse to a single binding for counting purposes.

    - PASS: The statement references at least two distinct PCR bindings.
    - FAIL: The statement references only PCR0 (or ImageSha384) and no other.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the KMS enclave PCR-breadth check.

        Iterates over enabled customer-managed KMS keys identified as enclave
        keys and evaluates each sensitive ``Allow`` statement's
        ``kms:RecipientAttestation:*`` condition keys. Collapses ``PCR0`` and
        ``ImageSha384`` into a single binding and reports FAIL when fewer than
        two distinct bindings remain.

        Returns:
            list[Check_Report_AWS]: One report per selected enclave KMS key.
        """
        findings = []
        for key in kms_client.keys:
            if (
                key.manager != "CUSTOMER"
                or key.state != "Enabled"
                or key.policy is None
                or not is_enclave_key(key)
            ):
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=key)
            report.status = "PASS"
            report.status_extended = (
                f"KMS enclave key {key.id} attestation conditions bind at least two "
                f"distinct PCR values (or PCR0 combined with another binding)."
            )

            statements = key.policy.get("Statement") or []
            if isinstance(statements, dict):
                statements = [statements]

            for statement in statements:
                if not isinstance(statement, dict):
                    continue
                if statement.get("Effect") != "Allow":
                    continue
                if not statement_targets_sensitive_actions(statement):
                    continue

                raw_keys = attestation_condition_keys(statement)
                if not raw_keys:
                    continue

                bindings = collapse_pcr0_and_imagesha384(raw_keys)
                if len(bindings) < 2:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"KMS enclave key {key.id} attestation binding is too narrow: "
                        f"only {sorted(bindings)} enforced. Add at least one more PCR "
                        f"(e.g., PCR1, PCR2, PCR4, PCR8) for defense-in-depth."
                    )
                    break
            findings.append(report)
        return findings
