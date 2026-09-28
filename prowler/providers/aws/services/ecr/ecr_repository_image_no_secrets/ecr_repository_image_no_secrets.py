import re

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.ecr.ecr_client import ecr_client

_SAFE_ENVIRONMENT_VARIABLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class ecr_repository_image_no_secrets(Check):
    """Ensure the latest ECR repository image embeds no hardcoded secrets.

    The most recently pushed image in every ECR repository is resolved to a
    single scannable manifest (a multi-arch image resolves to one platform's
    manifest; other architectures in the same manifest list are not
    scanned) and scanned for plaintext secrets in its configuration
    (environment variables, build history) and every filesystem layer's
    file contents. Older tagged images are not scanned.
    - PASS: no secrets detected and the whole image was scanned.
    - FAIL: a potential secret was detected; the variable, build step, or
      file is reported, never the secret value.
    - MANUAL: the image could not be scanned in full, so a clean result would
      be misleading -- the manifest could not be retrieved or resolved, the
      scan itself failed, or part of the image exceeded configured size limits
      or could not be retrieved.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        secrets_ignore_patterns = ecr_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = ecr_client.audit_config.get("secrets_validate", False)

        # Phase 1: collect. The service yields (repository, image, scan_data)
        # lazily, downloading each image's manifest, config, and layers; each
        # image contributes an env/history/file payload per scannable unit so
        # a finding's key maps back to a variable, build step, or file.
        scanned = []

        def image_payloads():
            """Yield keyed scan payloads, recording each image into `scanned`."""
            for repository, image, scan_data in ecr_client._get_image_scan_data():
                index = len(scanned)
                scanned.append((repository, image, scan_data))
                if scan_data is None or isinstance(scan_data, Exception):
                    continue
                for env_index, entry in enumerate(scan_data.env):
                    yield (index, f"environment:{env_index}"), entry
                for history_index, entry in enumerate(scan_data.history):
                    yield (index, f"history:{history_index}"), entry
                for file_index, scanned_file in enumerate(scan_data.files):
                    yield (index, f"file:{file_index}"), scanned_file.content
                    # Free the file's contents once handed to the scanner. The
                    # report phase needs only its path and layer digest, so
                    # retained memory stays flat instead of growing with the
                    # number of repositories scanned.
                    scanned_file.content = ""

        # Phase 2: batch — one call, chunked Kingfisher subprocesses. This
        # must fully consume image_payloads() so every image is appended to
        # `scanned` before Phase 3 runs; detect_secrets_scan_batch does so
        # today, but a future short-circuit there would silently drop images
        # from the report loop.
        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                image_payloads(),
                excluded_secrets=secrets_ignore_patterns,
                validate=validate,
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        if scan_error:
            # The scan failed and the payload generator may not have been
            # consumed, so build the MANUAL reports from the repositories
            # themselves rather than risk a false PASS or a missing finding.
            for registry in ecr_client.registries.values():
                for repository in registry.repositories:
                    image = ecr_client._get_scan_target_image(repository)
                    if isinstance(image, Exception):
                        findings.append(
                            self._build_scan_error_report(repository, image)
                        )
                    elif image is not None:
                        report = self._build_report(repository, image)
                        report.status = "MANUAL"
                        report.status_extended = (
                            f"Could not scan image '{image.latest_tag}' "
                            f"({image.latest_digest}) of ECR repository "
                            f"{repository.name} for secrets: {scan_error}; "
                            f"manual review is required."
                        )
                        findings.append(report)
            return findings

        # Phase 3: report — one finding per scanned image.
        for index, (repository, image, scan_data) in enumerate(scanned):
            if isinstance(scan_data, Exception):
                findings.append(self._build_scan_error_report(repository, scan_data))
                continue
            report = self._build_report(repository, image)
            image_reference = (
                f"image '{image.latest_tag}' ({image.latest_digest}) of ECR "
                f"repository {repository.name}"
            )

            if scan_data is None:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not resolve or retrieve the manifest of the "
                    f"{image_reference} to scan it for secrets; manual "
                    f"review is required."
                )
                findings.append(report)
                continue

            env_findings_by_index = {
                int(key[1].split(":", 1)[1]): entry_secrets
                for key, entry_secrets in batch_results.items()
                if key[0] == index and key[1].startswith("environment:")
            }
            history_findings_by_index = {
                int(key[1].split(":", 1)[1]): entry_secrets
                for key, entry_secrets in batch_results.items()
                if key[0] == index and key[1].startswith("history:")
            }
            file_findings_by_index = {
                int(key[1].split(":", 1)[1]): file_secrets
                for key, file_secrets in batch_results.items()
                if key[0] == index and key[1].startswith("file:")
            }

            if (
                env_findings_by_index
                or history_findings_by_index
                or file_findings_by_index
            ):
                secrets_found = []
                all_secrets = []

                for env_index, env_findings in env_findings_by_index.items():
                    variable = None
                    if 0 <= env_index < len(scan_data.env):
                        entry = scan_data.env[env_index]
                        # Only a well-formed "NAME=value" entry has a name safe
                        # to report; an entry with no "=" may itself be the
                        # secret, so it is never echoed back.
                        if "=" in entry:
                            candidate = entry.split("=", 1)[0]
                            if _SAFE_ENVIRONMENT_VARIABLE_NAME.fullmatch(candidate):
                                variable = candidate
                    all_secrets.extend(env_findings)
                    for secret in env_findings:
                        if variable is not None:
                            secrets_found.append(
                                f"{secret['type']} in environment variable {variable}"
                            )
                        else:
                            secrets_found.append(
                                f"{secret['type']} in image environment variables"
                            )
                for (
                    history_index,
                    history_findings,
                ) in history_findings_by_index.items():
                    all_secrets.extend(history_findings)
                    for secret in history_findings:
                        secrets_found.append(
                            f"{secret['type']} in image history step {history_index + 1}"
                        )
                for file_index, file_secrets in file_findings_by_index.items():
                    scanned_file = scan_data.files[file_index]
                    all_secrets.extend(file_secrets)
                    for secret in file_secrets:
                        secrets_found.append(
                            f"{secret['type']} in file {scanned_file.path} "
                            f"(layer {scanned_file.layer_digest})"
                        )

                report.status = "FAIL"
                report.status_extended = (
                    f"Potential {'secrets' if len(secrets_found) > 1 else 'secret'} "
                    f"found in the {image_reference} -> {', '.join(secrets_found)}."
                )
                if scan_data.truncated:
                    report.status_extended += (
                        " Some of the image could not be retrieved or exceeded "
                        "configured size limits and was not scanned."
                    )
                annotate_verified_secrets(report, all_secrets)
            elif scan_data.truncated:
                # No secrets in what was scanned, but coverage was incomplete
                # (size/count limits, or the config could not be retrieved), so
                # a clean result would be misleading.
                report.status = "MANUAL"
                report.status_extended = (
                    f"No secrets were found in the scanned portion of the "
                    f"{image_reference}, but part of it could not be retrieved "
                    f"or exceeded configured size limits and was not scanned; "
                    f"manual review is required."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"No secrets found in the {image_reference}."

            findings.append(report)

        return findings

    def _build_scan_error_report(self, repository, error) -> Check_Report_AWS:
        """Build a repository-level report for a latest-image lookup failure."""
        report = Check_Report_AWS(metadata=self.metadata(), resource=repository)
        report.status = "MANUAL"
        report.status_extended = (
            f"Could not determine the latest image of ECR repository "
            f"{repository.name}: {error}; manual review is required."
        )
        return report

    def _build_report(self, repository, image) -> Check_Report_AWS:
        """Build a report scoped to a single image within a repository.

        ECR images have no ARN of their own, so the repository's ARN is
        reused with the image digest appended as a synthetic suffix,
        mirroring how other sub-resource checks (e.g. CodeArtifact packages
        within a repository) identify per-item findings.
        """
        report = Check_Report_AWS(metadata=self.metadata(), resource=repository)
        digest_short = image.latest_digest.split(":")[-1][:12]
        report.resource_id = f"{repository.name}:{image.latest_tag}@{digest_short}"
        report.resource_arn = f"{repository.arn}/image/{digest_short}"
        return report
