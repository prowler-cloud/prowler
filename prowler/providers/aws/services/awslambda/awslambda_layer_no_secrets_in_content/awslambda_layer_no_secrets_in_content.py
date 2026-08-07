import fnmatch
import os
import tempfile
from collections import defaultdict

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.logger import logger
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_layer_no_secrets_in_content(Check):
    """Check if Lambda layer content contains hardcoded secrets.

    Scans every file inside each Lambda layer version's package with the
    secret scanner.

    - PASS: No secrets are detected in the layer content.
    - FAIL: At least one potential secret is detected in the layer content.
    - MANUAL: The layer content could not be fetched or scanned.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Lambda layer secrets scan.

        Returns:
            list[Check_Report_AWS]: One report per Lambda layer version used by
            the audited functions, or an empty list when there are no layers.
        """
        findings = []
        if not awslambda_client.layers:
            return findings

        secrets_ignore_patterns = awslambda_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        # Glob patterns of file names inside the layer package to skip
        # when scanning for secrets (e.g. "*.deps.json" for .NET layers).
        secrets_ignore_files = (
            awslambda_client.audit_config.get("secrets_ignore_files", []) or []
        )
        validate = awslambda_client.audit_config.get("secrets_validate", False)

        # Scan files of every layer version's package in batched
        # Kingfisher invocations instead of one subprocess per file per layer.
        # Each package is extracted one at a time and its files are
        # read (byte-faithfully via latin-1) before the extraction is released,
        # so only a single package is on disk at a time. Findings are keyed by
        # (layer index, package-relative file name) so they can be grouped
        # back per layer.
        layers_with_code = []

        def code_payloads():
            for layer, layer_code in awslambda_client._get_layers_code():
                if not layer_code:
                    continue
                with tempfile.TemporaryDirectory() as tmp_dir_name:
                    try:
                        layer_code.code_zip.extractall(tmp_dir_name)
                    except Exception as error:
                        # A corrupt or truncated package must not abort the
                        # scan of the remaining layers: keep this layer out of
                        # layers_with_code so it is reported as MANUAL below.
                        logger.error(
                            f"{layer.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                        continue
                    index = len(layers_with_code)
                    layers_with_code.append(layer)
                    for root, _, files in os.walk(tmp_dir_name):
                        for file_name in files:
                            file_path = os.path.join(root, file_name)
                            relative_file_path = os.path.relpath(
                                file_path, tmp_dir_name
                            )
                            if any(
                                fnmatch.fnmatch(relative_file_path, pattern)
                                for pattern in secrets_ignore_files
                            ):
                                continue
                            try:
                                with open(file_path, "rb") as code_file:
                                    content = code_file.read().decode("latin-1")
                            except Exception:
                                continue
                            yield (index, relative_file_path), content

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                code_payloads(),
                excluded_secrets=secrets_ignore_patterns,
                validate=validate,
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        if scan_error:
            # The scan failed before any layer's code could be cleared. Report
            # MANUAL for every layer rather than risk a false PASS.
            for layer in awslambda_client.layers.values():
                report = Check_Report_AWS(metadata=self.metadata(), resource=layer)
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan Lambda layer {layer.name} (version "
                    f"{layer.version}) content for secrets: {scan_error}; "
                    "manual review is required."
                )
                findings.append(report)
            return findings

        findings_by_layer = defaultdict(dict)
        for (index, file_name), file_findings in batch_results.items():
            findings_by_layer[index][file_name] = file_findings

        for index, layer in enumerate(layers_with_code):
            report = Check_Report_AWS(metadata=self.metadata(), resource=layer)
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Lambda layer {layer.name} "
                f"(version {layer.version}) content."
            )

            files_with_secrets = findings_by_layer.get(index)
            if files_with_secrets:
                all_secrets = []
                secrets_findings = []
                for file_name, file_findings in files_with_secrets.items():
                    all_secrets.extend(file_findings)
                    secrets_string = ", ".join(
                        f"{secret['type']} on line {secret['line_number']}"
                        for secret in file_findings
                    )
                    secrets_findings.append(f"{file_name}: {secrets_string}")

                final_output_string = "; ".join(secrets_findings)
                report.status = "FAIL"
                report.status_extended = f"Potential {'secrets' if len(secrets_findings) > 1 else 'secret'} found in Lambda layer {layer.name} (version {layer.version}) content -> {final_output_string}."
                annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        # Layers whose content could not be fetched (network error, missing
        # permissions, etc.) never reach layers_with_code above, so report
        # them as MANUAL rather than silently omitting them from the scan.
        fetched_arns = {layer.arn for layer in layers_with_code}
        for layer in awslambda_client.layers.values():
            if layer.arn in fetched_arns:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=layer)
            report.status = "MANUAL"
            report.status_extended = (
                f"Could not retrieve content of Lambda layer {layer.name} "
                f"(version {layer.version}) to scan for secrets; manual "
                "review is required."
            )
            findings.append(report)

        return findings
