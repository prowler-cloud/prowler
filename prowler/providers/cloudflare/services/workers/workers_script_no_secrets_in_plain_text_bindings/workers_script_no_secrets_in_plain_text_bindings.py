import json

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.cloudflare.services.workers.workers_client import (
    workers_client,
)
from prowler.providers.cloudflare.services.workers.workers_manual import (
    workers_manual_reports,
)


class workers_script_no_secrets_in_plain_text_bindings(Check):
    """Ensure that Workers plain text bindings do not contain secrets.

    Plain text bindings (`vars`) are stored and displayed unencrypted in the
    dashboard, API and deployment tooling. Credentials must be stored as
    `secret_text` bindings (Worker secrets) or in Secrets Store instead.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Scan the plain text and JSON bindings of every Worker for secrets.

        Returns:
            FAIL when a potential secret is found, PASS when none is found,
            MANUAL when the secrets scanner failed, and MANUAL per account whose
            Workers settings could not be retrieved.
        """
        findings = workers_manual_reports(
            self,
            workers_client,
            workers_client.settings_failed_accounts,
            "secrets in plain text and JSON bindings",
        )
        secrets_ignore_patterns = workers_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = workers_client.audit_config.get("secrets_validate", False)
        # Scripts whose bindings could not be retrieved are covered by the
        # account-level MANUAL finding, never by a "no secrets found" PASS.
        scripts = [
            script
            for script in workers_client.scripts
            if script.plain_text_bindings is not None
        ]

        def bindings_payloads():
            for index, script in enumerate(scripts):
                if script.plain_text_bindings:
                    yield index, json.dumps(script.plain_text_bindings, indent=2)

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                bindings_payloads(),
                excluded_secrets=secrets_ignore_patterns,
                validate=validate,
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for index, script in enumerate(scripts):
            report = CheckReportCloudflare(metadata=self.metadata(), resource=script)
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Worker {script.name} plain text bindings."
            )

            if script.plain_text_bindings:
                if scan_error:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not scan Worker {script.name} plain text bindings "
                        f"for secrets: {scan_error}; manual review is required."
                    )
                    findings.append(report)
                    continue

                secrets_found = batch_results.get(index)
                if secrets_found:
                    # json.dumps(indent=2) puts the first key on line 2.
                    binding_names = list(script.plain_text_bindings.keys())
                    secrets_string = ", ".join(
                        (
                            f"{secret['type']} in binding {binding_names[secret['line_number'] - 2]}"
                            if 0 <= secret["line_number"] - 2 < len(binding_names)
                            else secret["type"]
                        )
                        for secret in secrets_found
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Potential secret found in Worker {script.name} plain text bindings -> {secrets_string}."
                    annotate_verified_secrets(report, secrets_found)

            findings.append(report)
        return findings
