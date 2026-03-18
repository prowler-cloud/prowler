from prowler.lib.check.models import Check, CheckResult, CheckStatus
from prowler.providers.github.services.repository.repository_client import repository_client

class repository_ruleset_dismisses_stale_reviews(Check):
    def execute(self):
        findings = []
        for repo in repository_client.repositories.values():
            report = CheckResult(
                check_metadata=self.metadata(),
                resource_id=repo.full_name,
                resource_name=repo.full_name,
                resource_tags=[],
                region=repo.owner,
            )
            if repo.archived:
                report.status = CheckStatus.MANUAL
                report.status_extended = f"Repository {repo.full_name} is archived and not actively maintained."
                findings.append(report)
                continue
            if repo.rulesets:
                passing_ruleset = next((rs for rs in repo.rulesets if rs.enforcement == "active" and rs.dismiss_stale_reviews_on_push), None)
                if passing_ruleset:
                    report.status = CheckStatus.PASS
                    report.status_extended = f"Repository {repo.full_name} has an active ruleset '{passing_ruleset.name}' that dismisses stale reviews on push."
                else:
                    report.status = CheckStatus.FAIL
                    report.status_extended = f"Repository {repo.full_name} has rulesets but none enforce dismissal of stale reviews on push."
                findings.append(report)
                continue
            branch = repo.default_branch
            if branch is None or branch.protected is None:
                report.status = CheckStatus.MANUAL
                report.status_extended = f"Repository {repo.full_name}: branch protection status could not be determined."
                findings.append(report)
                continue
            if not branch.protected:
                report.status = CheckStatus.FAIL
                report.status_extended = f"Repository {repo.full_name} default branch '{branch.name}' has no branch protection or ruleset configured."
                findings.append(report)
                continue
            report.status = CheckStatus.MANUAL
            report.status_extended = f"Repository {repo.full_name} uses legacy branch protection rules. Migrate to GitHub Repository Rulesets and enable 'Dismiss stale reviews on push' to allow automated verification."
            findings.append(report)
        return findings
