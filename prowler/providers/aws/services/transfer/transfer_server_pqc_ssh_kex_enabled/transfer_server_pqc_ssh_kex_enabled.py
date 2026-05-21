from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.transfer.transfer_client import transfer_client

PQC_TRANSFER_POLICIES_DEFAULT = [
    "TransferSecurityPolicy-2025-03",
    "TransferSecurityPolicy-FIPS-2025-03",
    "TransferSecurityPolicy-AS2Restricted-2025-07",
]


class transfer_server_pqc_ssh_kex_enabled(Check):
    """Verify that every AWS Transfer Family server uses a post-quantum security policy.

    A Transfer Family server PASSES when its ``SecurityPolicyName`` is in the
    configured allowlist of policies that enable hybrid ML-KEM SSH key exchange.
    """

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        pqc_policies = transfer_client.audit_config.get(
            "transfer_pqc_ssh_allowed_policies", PQC_TRANSFER_POLICIES_DEFAULT
        )
        for server in transfer_client.servers.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=server)
            policy = server.security_policy_name or "<none>"
            if server.security_policy_name in pqc_policies:
                report.status = "PASS"
                report.status_extended = (
                    f"Transfer Server {server.id} uses post-quantum security policy "
                    f"{policy}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Transfer Server {server.id} uses security policy {policy}, "
                    "which does not enable post-quantum hybrid SSH key exchange."
                )
            findings.append(report)

        return findings
