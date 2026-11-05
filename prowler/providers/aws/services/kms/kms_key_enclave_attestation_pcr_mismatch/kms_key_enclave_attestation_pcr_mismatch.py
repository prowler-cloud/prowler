from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.enclave import (
    GOLDEN_PCR_CONFIG_KEY,
    _pcr_to_bytes,
    attestation_values_by_pcr,
    is_enclave_key,
    normalize_golden_pcr_config,
    statement_targets_sensitive_actions,
)


class kms_key_enclave_attestation_pcr_mismatch(Check):
    """Ensure enclave KMS attestation PCRs match customer-supplied golden values.

    Compares the ``kms:RecipientAttestation:PCR<N>`` (and equivalent
    ``ImageSha384``) values referenced by every restrictive statement in the
    key policy against a customer-provided list of trusted PCR hashes from
    their audited enclave build pipeline. Detects supply-chain drift where a
    policy still references attestation but the attested measurement no longer
    corresponds to a known-good build.

    - MANUAL: no ``enclave_golden_pcr_values`` audit_config block, the block
      contains no usable PCR buckets, or the policy references at least one
      PCR ID for which no golden list is configured. The check cannot make a
      safe assertion; the operator must extend the golden list or review the
      uncovered PCRs by hand.
    - PASS: every PCR referenced by the policy is covered by the golden config
      *and* every referenced value is in its golden list.
    - FAIL: at least one referenced PCR value is not in its configured golden
      list.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the golden-PCR provenance check.

        Iterates enabled customer-managed KMS keys flagged as enclave keys and,
        for every sensitive ``Allow`` statement, aggregates the restrictive
        attestation values by PCR ID. When ``enclave_golden_pcr_values`` is
        configured, compares each PCR bucket that has a golden list against it
        (PCR buckets without a configured list are skipped for that key).

        Returns:
            list[Check_Report_AWS]: One report per selected enclave KMS key.
        """
        findings = []
        golden = normalize_golden_pcr_config(
            kms_client.audit_config.get(GOLDEN_PCR_CONFIG_KEY)
        )

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
                        f"fetched ({key.policy_fetch_error}); PCR provenance "
                        f"cannot be verified against the golden list."
                    )
                    findings.append(report)
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=key)

            if not golden:
                report.status = "MANUAL"
                report.status_extended = (
                    f"KMS enclave key {key.id} provenance cannot be verified: "
                    f"no 'enclave_golden_pcr_values' configured. Set a golden "
                    f"PCR list in audit_config and re-run this check."
                )
                findings.append(report)
                continue

            observed: dict = {}
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
                for pcr_id, values in attestation_values_by_pcr(statement).items():
                    observed.setdefault(pcr_id, set()).update(values)

            uncovered = sorted(observed.keys() - golden.keys())
            mismatches: list = []
            for pcr_id, allowed in golden.items():
                seen = observed.get(pcr_id)
                if not seen:
                    continue
                # Compare on canonical bytes (48 raw bytes from hex or
                # base64) so hex vs base64 mismatches between the golden
                # config and the policy do not produce false positives.
                allowed_bytes = {
                    b for a in allowed if (b := _pcr_to_bytes(a)) is not None
                }
                bad = sorted(
                    v
                    for v in seen
                    if (vb := _pcr_to_bytes(v)) is None or vb not in allowed_bytes
                )
                if bad:
                    mismatches.append((pcr_id, bad))

            if not observed:
                report.status = "MANUAL"
                report.status_extended = (
                    f"KMS enclave key {key.id} has no restrictive attestation "
                    f"bindings on sensitive statements; provenance cannot be "
                    f"verified against the golden list."
                )
            elif mismatches:
                report.status = "FAIL"
                details = "; ".join(f"{pcr}={bad}" for pcr, bad in sorted(mismatches))
                report.status_extended = (
                    f"KMS enclave key {key.id} references PCR values outside "
                    f"the configured golden list: {details}."
                )
            elif uncovered:
                report.status = "MANUAL"
                report.status_extended = (
                    f"KMS enclave key {key.id} references PCR IDs {uncovered} "
                    f"for which no golden list is configured; provenance "
                    f"cannot be verified. Extend 'enclave_golden_pcr_values' "
                    f"to cover them or review by hand."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"KMS enclave key {key.id} attestation PCR values all "
                    f"match the configured golden list."
                )
            findings.append(report)
        return findings
