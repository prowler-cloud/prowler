from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client

HIGH_RISK_FILTER_TYPES = {"ACTOR_ACCOUNT_ID", "HEAD_REF", "BASE_REF"}


def is_pattern_anchored(pattern: str) -> bool:
    """Check if each alternative in a pipe-separated pattern is anchored with ^ and $."""
    if not pattern:
        return True

    for alt in pattern.split("|"):
        alt = alt.strip()
        if alt and not (alt.startswith("^") and alt.endswith("$")):
            return False
    return True


class codebuild_project_webhook_filters_use_anchored_patterns(Check):
    def execute(self) -> List[Check_Report_AWS]:
        findings = []

        for project in codebuild_client.projects.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=project)
            report.status = "PASS"
            report.status_extended = (
                f"CodeBuild project {project.name} has no webhook configured or all "
                "webhook filter patterns are properly anchored."
            )

            if not project.webhook or not project.webhook.filter_groups:
                findings.append(report)
                continue

            unanchored_filters = []
            for filter_group in project.webhook.filter_groups:
                for webhook_filter in filter_group.filters:
                    if webhook_filter.type in HIGH_RISK_FILTER_TYPES:
                        if not is_pattern_anchored(webhook_filter.pattern):
                            unanchored_filters.append(
                                f"{webhook_filter.type}: '{webhook_filter.pattern}'"
                            )

            if unanchored_filters:
                report.status = "FAIL"
                filters_str = ", ".join(unanchored_filters[:3])
                if len(unanchored_filters) > 3:
                    filters_str += f" and {len(unanchored_filters) - 3} more"
                report.status_extended = (
                    f"CodeBuild project {project.name} has webhook filters with "
                    f"unanchored patterns that could allow bypass attacks: {filters_str}."
                )

            findings.append(report)

        return findings
