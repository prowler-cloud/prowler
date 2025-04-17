from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client
from prowler.providers.aws.services.iam.iam_client import iam_client

# Inspired by https://medium.com/@adan.alvarez/gaining-long-term-aws-access-with-codebuild-and-github-873324638784

class codebuild_backdoored_iam_roles_github_actions(Check):
    def execute(self):
        findings = []
        allowed_organizations = codebuild_client.audit_config.get(
            "codebuild_github_allowed_organizations", []
        )

        for project in codebuild_client.projects.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=project)
            report.status = "PASS"

            if project.source.type == "GITHUB":
                project_github_repo_url = project.source.location
                project_role = next((role for role in iam_client.roles if role.arn == project.service_role_arn), None)
                project_iam_trust_policy = project_role.assume_role_policy

                if project_iam_trust_policy:
                    if isinstance(project_iam_trust_policy["Statement"], list):
                        for statement in project_iam_trust_policy["Statement"]:
                            if (
                                statement["Effect"] == "Allow"
                                and "codebuild.amazonaws.com" in statement["Principal"]["Service"]
                            ):
                                if project_github_repo_url:
                                    org_name = project_github_repo_url.split("/")[3]
                                    if org_name not in allowed_organizations:
                                        report.status = "FAIL"
                                        report.status_extended = f"CodeBuild project {project.name} uses GitHub organization '{org_name}', which is not in the allowed organizations."
                                    else:
                                        report.status_extended = f"CodeBuild project {project.name} uses GitHub organization '{org_name}', which is in the allowed organizations."
                            else:
                                report.status_extended = f"CodeBuild project {project.name} does not use an IAM role with codebuild.amazonaws.com as a trusted principal, skipping GitHub organization check."

                findings.append(report)

        return findings