import base64

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.sagemaker.sagemaker_client import (
    sagemaker_client,
)


class sagemaker_notebook_instance_no_secrets(Check):
    def execute(self):
        findings = []
        notebook_instances = sagemaker_client.sagemaker_notebook_instances
        if not notebook_instances:
            return findings

        secrets_ignore_patterns = sagemaker_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = sagemaker_client.audit_config.get("secrets_validate", False)

        def payloads():
            for index, notebook_instance in enumerate(notebook_instances):
                if not notebook_instance.lifecycle_config_name:
                    continue
                try:
                    regional_client = sagemaker_client.regional_clients[
                        notebook_instance.region
                    ]
                    lifecycle_config = (
                        regional_client.describe_notebook_instance_lifecycle_config(
                            NotebookInstanceLifecycleConfigName=notebook_instance.lifecycle_config_name
                        )
                    )
                except Exception:
                    continue

                for hook_name in ("OnCreate", "OnStart"):
                    scripts = lifecycle_config.get(hook_name, [])
                    for script_index, script in enumerate(scripts):
                        content_b64 = script.get("Content")
                        if not content_b64:
                            continue
                        try:
                            decoded = base64.b64decode(content_b64).decode(
                                "utf-8", errors="ignore"
                            )
                        except Exception:
                            continue
                        yield (index, f"{hook_name}[{script_index}]"), decoded

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(),
                excluded_secrets=secrets_ignore_patterns,
                validate=validate,
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        if scan_error:
            for notebook_instance in notebook_instances:
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource=notebook_instance
                )
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan SageMaker notebook instance "
                    f"{notebook_instance.name} lifecycle config for secrets: "
                    f"{scan_error}; manual review is required."
                )
                findings.append(report)
            return findings

        findings_by_instance = {}
        for (index, fragment), fragment_findings in batch_results.items():
            findings_by_instance.setdefault(index, {})[fragment] = fragment_findings

        for index, notebook_instance in enumerate(notebook_instances):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=notebook_instance
            )
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in SageMaker notebook instance "
                f"{notebook_instance.name} lifecycle configuration."
            )

            fragments_with_secrets = findings_by_instance.get(index)
            if fragments_with_secrets:
                all_secrets = []
                secrets_findings = []
                for fragment, fragment_findings in fragments_with_secrets.items():
                    all_secrets.extend(fragment_findings)
                    secrets_string = ", ".join(
                        f"{secret['type']} on line {secret['line_number']}"
                        for secret in fragment_findings
                    )
                    secrets_findings.append(f"{fragment}: {secrets_string}")

                final_output_string = "; ".join(secrets_findings)
                report.status = "FAIL"
                report.status_extended = (
                    f"Potential {'secrets' if len(secrets_findings) > 1 else 'secret'} "
                    f"found in SageMaker notebook instance {notebook_instance.name} "
                    f"lifecycle configuration -> {final_output_string}."
                )
                annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        return findings