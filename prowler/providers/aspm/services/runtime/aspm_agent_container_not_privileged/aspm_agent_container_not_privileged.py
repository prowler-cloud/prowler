"""ASPM-058: AI agent container must not run privileged or as root."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.runtime.runtime_client import runtime_client


class aspm_agent_container_not_privileged(Check):
    """Check that AI agent containers run as non-root with mandatory isolation controls.

    A container is considered non-compliant when any of the following conditions
    are true: it runs as root, it uses a privileged container, it lacks a seccomp
    profile, or it lacks an AppArmor/SELinux policy.  All four controls must be
    satisfied to achieve meaningful container isolation.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in runtime_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            missing = []
            if agent.runtime.runs_as_root:
                missing.append("runs as root")
            if agent.runtime.privileged_container:
                missing.append("uses a privileged container")
            if not agent.runtime.has_seccomp_profile:
                missing.append("no seccomp profile")
            if not agent.runtime.has_apparmor_selinux:
                missing.append("no AppArmor/SELinux policy")

            if missing:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} container isolation is insufficient: "
                    + ", ".join(missing)
                    + "."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} container runs as non-root with "
                    "seccomp and AppArmor/SELinux applied."
                )
            findings.append(report)
        return findings
