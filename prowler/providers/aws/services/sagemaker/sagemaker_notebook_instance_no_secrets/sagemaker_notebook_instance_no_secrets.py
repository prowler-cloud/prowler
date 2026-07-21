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
    """Check for hardcoded secrets in SageMaker notebook instance lifecycle scripts.

    Scans the OnCreate and OnStart lifecycle configuration scripts of each
    SageMaker notebook instance for hardcoded secrets such as API keys,
    passwords, tokens, and connection strings. The scripts are fetched and
    decoded by the SageMaker service; this check only consumes that data.
    """

    def execute(self):
        """Execute the sagemaker_notebook_instance_no_secrets check.

        Returns:
            list[Check_Report_AWS]: One report per SageMaker notebook
                instance, with status PASS, FAIL, or MANUAL.
        """
        findings = []
        notebook_instances = sagemaker_client.sagemaker_notebook_instances
        if not notebook_instances:
            return findings

        secrets_ignore_patterns = sagemaker_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = sagemaker_client.audit_config.get("secrets_validate", False)

        # Instances that actually contribute a script to the batch. Only these
        # (plus instances whose describe/decode failed) may be marked MANUAL on
        # a batch scan failure; instances with nothing to scan must PASS.
        scanned_resources = {
            notebook_instance.arn
            for notebook_instance in notebook_instances
            if notebook_instance.lifecycle_scripts
        }

        def payloads():
            for notebook_instance in notebook_instances:
                for fragment, script in notebook_instance.lifecycle_scripts.items():
                    yield (notebook_instance.arn, fragment), script

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

        findings_by_instance = {}
        for (
            resource_id,
            fragment,
        ), fragment_findings in batch_results.items():
            findings_by_instance.setdefault(resource_id, {})[
                fragment
            ] = fragment_findings

        for notebook_instance in notebook_instances:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=notebook_instance
            )

            # MANUAL when the instance could not be fully scanned: either the
            # lifecycle config describe/decode failed, or the batch scan failed
            # for an instance that actually had scripts queued for scanning.
            batch_failed = (
                scan_error is not None and notebook_instance.arn in scanned_resources
            )
            if notebook_instance.lifecycle_scan_failed or batch_failed:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not fully scan SageMaker notebook instance "
                    f"{notebook_instance.name} lifecycle configuration for "
                    f"secrets; manual review is required."
                )
                findings.append(report)
                continue

            report.status = "PASS"
            if not notebook_instance.lifecycle_config_name:
                report.status_extended = (
                    f"SageMaker notebook instance {notebook_instance.name} "
                    f"does not have a lifecycle configuration."
                )
            else:
                report.status_extended = (
                    f"No secrets found in SageMaker notebook instance "
                    f"{notebook_instance.name} lifecycle configuration."
                )

            fragments_with_secrets = findings_by_instance.get(notebook_instance.arn)

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
                    f"found in SageMaker notebook instance "
                    f"{notebook_instance.name} lifecycle configuration -> "
                    f"{final_output_string}."
                )
                annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        return findings
