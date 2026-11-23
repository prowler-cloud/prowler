from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import (
    get_effective_actions,
    is_policy_public,
)
from prowler.providers.aws.services.oam.oam_client import oam_client

# The actions a sink policy grants so that source accounts can link to the sink.
LINK_ACTIONS = {"oam:CreateLink", "oam:UpdateLink"}


class oam_sink_not_publicly_accessible(Check):
    """Ensure Observability Access Manager sinks do not let any AWS account link to them."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            One report per sink: FAIL when its policy lets any AWS account create or
            update a link without a restrictive condition, PASS otherwise.
        """
        findings = []
        for sink in oam_client.sinks.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=sink)
            report.status = "PASS"
            report.status_extended = (
                f"OAM sink {sink.name} does not allow any AWS account to link to it."
            )

            statements = (sink.policy or {}).get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            # Statements that only grant read-only actions cannot link, however public they are
            link_statements = [
                statement
                for statement in statements
                if get_effective_actions({"Statement": [statement]}) & LINK_ACTIONS
            ]
            if is_policy_public(
                {"Statement": link_statements}, oam_client.audited_account
            ):
                report.status = "FAIL"
                report.status_extended = (
                    f"OAM sink {sink.name} allows any AWS account to link to it."
                )

            findings.append(report)

        return findings
