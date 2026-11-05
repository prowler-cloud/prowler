from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.enclave import (
    attestation_condition_keys,
    is_enclave_key,
    statement_targets_sensitive_actions,
)


class kms_key_enclave_attestation_not_enforced(Check):
    """Ensure enclave-scoped KMS keys require attestation on sensitive actions.

    KMS keys that back Nitro Enclave workloads are identified by the explicit
    ``prowler:enclave-key=true`` tag, or by the substring ``enclave`` in the
    key description or any tag key/value. Every ``Allow`` statement in the
    key policy that grants a sensitive action (``kms:Decrypt``,
    ``kms:DeriveSharedSecret``, ``kms:GenerateDataKey``,
    ``kms:GenerateDataKeyPair``, ``kms:GenerateRandom``, ``kms:*``, ``*``)
    must carry at least one ``kms:RecipientAttestation:*`` condition.

    - PASS: Every sensitive Allow statement carries an attestation condition.
    - FAIL: At least one sensitive Allow statement is unconditioned.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the KMS enclave-attestation-condition check.

        Iterates over enabled customer-managed KMS keys tagged/described as
        enclave keys and walks their policy statements looking for sensitive
        ``Allow`` statements that lack a ``kms:RecipientAttestation:*``
        condition key.

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
                        f"fetched ({key.policy_fetch_error}); attestation "
                        f"enforcement cannot be verified."
                    )
                    findings.append(report)
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=key)
            report.status = "PASS"
            report.status_extended = (
                f"KMS enclave key {key.id} enforces attestation on every sensitive "
                f"Allow statement."
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
                if not attestation_condition_keys(statement):
                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    action_names = [a for a in actions if isinstance(a, str)]
                    actions_str = (
                        ", ".join(sorted(action_names)) if action_names else "<none>"
                    )
                    report.status = "FAIL"
                    report.status_extended = (
                        f"KMS enclave key {key.id} allows sensitive action(s) "
                        f"{actions_str} without any kms:RecipientAttestation:* "
                        f"condition."
                    )
                    break
            findings.append(report)
        return findings
