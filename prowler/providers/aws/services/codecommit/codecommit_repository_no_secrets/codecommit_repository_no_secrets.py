from collections import defaultdict
from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.codecommit.codecommit_client import (
    codecommit_client,
)


class codecommit_repository_no_secrets(Check):
    """Ensure CodeCommit repositories do not contain hardcoded secrets.

    Scans every file tracked at the tip of each repository's default branch
    for embedded credentials such as API keys, tokens, or passwords. Only the
    default branch at its current commit is scanned by default; full commit
    history is not walked, since secrets that persist in history but have
    been removed from the tip of the branch are out of scope for this check.

    - PASS: No secrets are detected in the files of the default branch.
    - FAIL: A secret is detected in one or more files of the default branch.
    - MANUAL: The secret scan could not be completed and requires manual review.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """Execute the CodeCommit repository secrets check.

        Iterates over all discovered repositories, scans every file at the
        tip of the default branch for secrets in batched invocations, and
        reports any findings, including the repository, branch, commit, and
        file where the secret was found (never the secret value itself).

        Returns:
            List[Check_Report_AWS]: A list of report objects with check results.
        """
        findings = []
        secrets_ignore_patterns = codecommit_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = codecommit_client.audit_config.get("secrets_validate", False)
        repositories = (
            list(codecommit_client.repositories.values())
            if codecommit_client.repositories
            else []
        )

        # Collect every file tracked at the tip of each repository's default
        # branch and scan them in batched invocations instead of one
        # subprocess per file. Findings are keyed by (repository index, file
        # path) so they can be grouped back per repository.
        def payloads():
            for repo_index, repository in enumerate(repositories):
                if (
                    not repository.default_branch
                    or not repository.default_branch_commit_id
                ):
                    continue
                for (
                    file_path,
                    file_content,
                ) in codecommit_client.get_repository_files_content(repository):
                    if not file_content:
                        continue
                    yield (repo_index, file_path), file_content.decode("latin-1")

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(), excluded_secrets=secrets_ignore_patterns, validate=validate
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        findings_by_repository = defaultdict(dict)
        for (repo_index, file_path), file_findings in batch_results.items():
            findings_by_repository[repo_index][file_path] = file_findings

        for repo_index, repository in enumerate(repositories):
            report = Check_Report_AWS(metadata=self.metadata(), resource=repository)
            report.status = "PASS"
            report.status_extended = f"CodeCommit repository {repository.name} does not have secrets in its default branch."

            has_default_branch = bool(
                repository.default_branch and repository.default_branch_commit_id
            )

            if scan_error and has_default_branch:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan CodeCommit repository {repository.name} "
                    f"default branch for secrets: {scan_error}; manual review is required."
                )
                findings.append(report)
                continue

            files_with_secrets = findings_by_repository.get(repo_index)
            if files_with_secrets:
                all_secrets = []
                secrets_found = []
                for file_path, file_findings in files_with_secrets.items():
                    all_secrets.extend(file_findings)
                    secrets_found.extend(
                        f"{file_path} on line {secret['line_number']} ({secret['type']})"
                        for secret in file_findings
                    )

                secrets_string = ", ".join(secrets_found)
                report.status = "FAIL"
                report.status_extended = (
                    f"CodeCommit repository {repository.name} has "
                    f"{'secrets' if len(secrets_found) > 1 else 'a secret'} in branch "
                    f"{repository.default_branch} (commit {repository.default_branch_commit_id}) -> {secrets_string}."
                )
                annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        return findings
