from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.ecr.ecr_client import ecr_client


class ecr_repository_image_no_secrets(Check):
    """Ensure the latest ECR repository image embeds no hardcoded secrets.

    The most recently pushed image in every ECR repository is resolved to a
    single scannable manifest (a multi-arch image resolves to one platform's
    manifest; other architectures in the same manifest list are not
    scanned) and scanned for plaintext secrets in its configuration
    (environment variables, build history) and every filesystem layer's
    file contents. Older tagged images are not scanned.
    - PASS: no secrets detected. Layers or files skipped for exceeding a
      configured size limit are disclosed in the message, not silently
      treated as clean.
    - FAIL: a potential secret was detected; the variable, build step, or
      file is reported, never the secret value.
    - MANUAL: the image manifest could not be retrieved or resolved, or the
      scan itself failed.
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
            for repository, image, scan_data in ecr_client._get_image_scan_data():
                index = len(scanned)
                scanned.append((repository, image, scan_data))
                if scan_data is None:
                    continue
                if scan_data.env:
                    yield (index, "environment"), "\n".join(scan_data.env)
                if scan_data.history:
                    yield (index, "history"), "\n".join(scan_data.history)
                for file_index, scanned_file in enumerate(scan_data.files):
                    yield (index, f"file:{file_index}"), scanned_file.content

        # Phase 2: batch — one call, chunked Kingfisher subprocesses.
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
                    for image in repository.images_details or []:
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

            report.status = "PASS"
            report.status_extended = f"No secrets found in the {image_reference}."
            if scan_data.truncated:
                report.status_extended += (
                    " Some layers or files exceeded configured size limits "
                    "and were not scanned."
                )

            env_findings = batch_results.get((index, "environment"), [])
            history_findings = batch_results.get((index, "history"), [])
            file_findings_by_index = {
                int(key[1].split(":", 1)[1]): file_secrets
                for key, file_secrets in batch_results.items()
                if key[0] == index and key[1].startswith("file:")
            }

            if env_findings or history_findings or file_findings_by_index:
                secrets_found = []
                all_secrets = list(env_findings) + list(history_findings)

                for secret in env_findings:
                    line_index = secret["line_number"] - 1
                    if 0 <= line_index < len(scan_data.env):
                        variable = scan_data.env[line_index].split("=", 1)[0]
                        secrets_found.append(
                            f"{secret['type']} in environment variable {variable}"
                        )
                    else:
                        secrets_found.append(
                            f"{secret['type']} in image environment variables"
                        )
                for secret in history_findings:
                    secrets_found.append(
                        f"{secret['type']} in image history step {secret['line_number']}"
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
                annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        return findings

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
