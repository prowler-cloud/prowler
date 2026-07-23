from prowler.lib.check.models import Check, CheckReportStackIT
from prowler.providers.stackit.services.ske.ske_client import ske_client


class ske_cluster_no_public_endpoint(Check):
    """
    Check if SKE clusters expose their Kubernetes API endpoint to the internet.

    A cluster passes when its control plane is confined to a STACKIT Network
    Area, or when the ACL extension restricts the Kubernetes API to a set of
    source CIDRs that does not include an unrestricted range.
    """

    def execute(self) -> list[CheckReportStackIT]:
        """
        Execute the check for all SKE clusters in the StackIT project.

        Returns:
            list: A list of CheckReportStackIT findings
        """
        findings = []

        for cluster in ske_client.clusters:
            report = CheckReportStackIT(
                metadata=self.metadata(),
                resource=cluster,
            )

            if cluster.has_public_endpoint():
                report.status = "FAIL"
                unrestricted_cidrs = cluster.unrestricted_cidrs()
                if unrestricted_cidrs:
                    report.status_extended = (
                        f"SKE cluster {cluster.name} exposes its Kubernetes API "
                        f"endpoint to the internet because its ACL allows "
                        f"unrestricted access from {', '.join(unrestricted_cidrs)}."
                    )
                else:
                    report.status_extended = (
                        f"SKE cluster {cluster.name} exposes its Kubernetes API "
                        f"endpoint to the internet because the ACL extension is "
                        f"not enabled."
                    )
            else:
                report.status = "PASS"
                if cluster.has_private_control_plane():
                    report.status_extended = (
                        f"SKE cluster {cluster.name} has a private control plane "
                        f"and its Kubernetes API endpoint is not reachable from "
                        f"the internet."
                    )
                else:
                    report.status_extended = (
                        f"SKE cluster {cluster.name} restricts access to its "
                        f"Kubernetes API endpoint to "
                        f"{len(cluster.allowed_cidrs)} allowed CIDR(s)."
                    )

            findings.append(report)

        return findings
