from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.enclave import (
    attestation_condition_keys,
    is_enclave_key,
    statement_is_covered_by_deny,
    statement_targets_sensitive_actions,
)


class kms_key_enclave_attestation_bypassable_path(Check):
    """Ensure every authorization path to an enclave KMS key requires attestation.

    A key policy has a **bypass path** when at least one ``Allow`` statement
    grants a sensitive action (``kms:Decrypt``, ``kms:DeriveSharedSecret``,
    ``kms:GenerateDataKey``, ``kms:GenerateDataKeyPair``,
    ``kms:GenerateRandom``, ``kms:*``, ``*``) without a restrictive
    ``kms:RecipientAttestation:*`` condition and without a paired ``Deny``
    that fires when attestation is absent. A caller with IAM permission on
    the key can use that bypass path to access material without ever
    presenting a valid attestation document — including the common
    ``AdminNoDataActions`` shape when it uses ``kms:*`` on the root
    principal.

    - PASS: every sensitive Allow enforces attestation, or unconditioned
      Allows are neutralized by a Deny statement that requires attestation.
    - FAIL: at least one authorization path bypasses attestation and no
      Deny neutralizes it.

    Not covered (documented limitations): existing KMS grants
    (``kms:list_grants`` is not captured by the service layer); IAM policies
    global to the account (evaluating every principal is out of scope). If
    the account-level IAM surface is a concern, complement this check with
    ``kms_key_not_publicly_accessible`` and ``kms_key_enclave_attestation_not_enforced``.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the bypassable-path check.

        Iterates enabled customer-managed KMS keys flagged as enclave keys
        and, for each policy, looks for the first sensitive Allow statement
        that (a) does not carry an attestation condition and (b) is not
        neutralized by a matching Deny. Emits FAIL when found, PASS
        otherwise.

        Returns:
            list[Check_Report_AWS]: one report per enclave KMS key.
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
                        f"fetched ({key.policy_fetch_error}); bypass paths "
                        f"cannot be evaluated."
                    )
                    findings.append(report)
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=key)
            statements = key.policy.get("Statement") or []
            if isinstance(statements, dict):
                statements = [statements]

            bypass = None
            for stmt in statements:
                if not isinstance(stmt, dict):
                    continue
                if stmt.get("Effect") != "Allow":
                    continue
                if not statement_targets_sensitive_actions(stmt):
                    continue
                if attestation_condition_keys(stmt):
                    continue
                if statement_is_covered_by_deny(stmt, key.policy):
                    continue
                bypass = stmt
                break

            if bypass:
                sid = bypass.get("Sid") or "(no Sid)"
                report.status = "FAIL"
                report.status_extended = (
                    f"KMS enclave key {key.id} exposes a bypass path in "
                    f"statement '{sid}': sensitive actions are allowed "
                    f"without kms:RecipientAttestation:* and no Deny "
                    f"neutralizes the gap. Any IAM principal permitted on "
                    f"the key can access material without presenting "
                    f"attestation."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"KMS enclave key {key.id} has no bypass paths: every "
                    f"sensitive Allow enforces attestation or is "
                    f"neutralized by an explicit Deny."
                )
            findings.append(report)
        return findings
