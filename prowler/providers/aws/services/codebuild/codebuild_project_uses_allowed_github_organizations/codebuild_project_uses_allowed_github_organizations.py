from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import (
    has_codebuild_trusted_principal,
    is_codebuild_using_allowed_github_org,
)


class codebuild_project_uses_allowed_github_organizations(Check):
    def execute(self):
        findings = []
        allowed_organizations = codebuild_client.audit_config.get(
            "codebuild_github_allowed_organizations", []
        )

        for project in codebuild_client.projects.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=project)
            report.status = "PASS"

            if project.source.type in ("GITHUB", "GITHUB_ENTERPRISE"):
                project_github_repo_url = project.source.location
                project_role = next(
                    (
                        role
                        for role in iam_client.roles
                        if role.arn == project.service_role_arn
                    ),
                    None,
                )
                project_iam_trust_policy = (
                    project_role.assume_role_policy if project_role else None
                )

                if project_iam_trust_policy:
                    if not has_codebuild_trusted_principal(project_iam_trust_policy):
                        report.status_extended = f"CodeBuild project {project.name} does not use an IAM role with codebuild.amazonaws.com as a trusted principal, skipping GitHub organization check."
                    else:
                        is_allowed, org_name = is_codebuild_using_allowed_github_org(
                            project_iam_trust_policy,
                            project_github_repo_url,
                            allowed_organizations,
                        )
                        if org_name is not None:
                            if is_allowed:
                                report.status_extended = f"CodeBuild project {project.name} uses GitHub organization '{org_name}', which is in the allowed organizations."
                            else:
                                report.status = "FAIL"
                                report.status_extended = f"CodeBuild project {project.name} uses GitHub organization '{org_name}', which is not in the allowed organizations."
                        else:
                            report.status_extended = f"CodeBuild project {project.name} uses a GitHub repository with an invalid or unrecognized organization in the URL."
                else:
                    report.status_extended = f"CodeBuild project {project.name} does not use an IAM role with codebuild.amazonaws.com as a trusted principal, skipping GitHub organization check."

                findings.append(report)

        return findings
