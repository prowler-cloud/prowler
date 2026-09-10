import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_client import (
    elasticbeanstalk_client,
)


class elasticbeanstalk_environment_no_secrets_in_configuration(Check):
    """Check that Elastic Beanstalk environment configurations contain no hardcoded secrets."""

    def execute(self) -> list[Check_Report_AWS]:
        """Scan the option settings of each Elastic Beanstalk environment for secrets.

        Every option setting is scanned as ``{OptionName: Value}`` so the scanner
        gets the same name context the other secrets checks provide. Findings are
        keyed by ``(environment index, option setting index)`` because the same
        namespace and option name can appear more than once per environment (one
        entry per ``ResourceName``).

        Returns:
            list[Check_Report_AWS]: A report for each Elastic Beanstalk environment.
        """
        findings = []
        secrets_ignore_patterns = elasticbeanstalk_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = elasticbeanstalk_client.audit_config.get("secrets_validate", False)
        environments = list(elasticbeanstalk_client.environments.values())

        # Phase 1: collect — build the payload strings only, no scan yet.
        def payloads():
            for environment_index, environment in enumerate(environments):
                for option_index, option_setting in enumerate(
                    environment.option_settings or []
                ):
                    value = option_setting.get("Value")
                    if not value:
                        continue
                    yield (environment_index, option_index), json.dumps(
                        {option_setting.get("OptionName", ""): value}
                    )

        # Phase 2: batch — one scan for every environment.
        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(), excluded_secrets=secrets_ignore_patterns, validate=validate
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        # Phase 3: report — one finding per environment.
        for environment_index, environment in enumerate(environments):
            report = Check_Report_AWS(metadata=self.metadata(), resource=environment)

            if environment.option_settings is None:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not retrieve the configuration of Elastic Beanstalk "
                    f"environment {environment.name}; manual review is required."
                )
                findings.append(report)
                continue

            if scan_error and any(
                option_setting.get("Value")
                for option_setting in environment.option_settings
            ):
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan the configuration of Elastic Beanstalk "
                    f"environment {environment.name} for secrets; manual review is required."
                )
                findings.append(report)
                continue

            report.status = "PASS"
            report.status_extended = f"No secrets found in the configuration of Elastic Beanstalk environment {environment.name}."

            secret_settings = []
            all_secrets = []
            for option_index, option_setting in enumerate(environment.option_settings):
                detect_secrets_output = batch_results.get(
                    (environment_index, option_index)
                )
                if detect_secrets_output:
                    all_secrets.extend(detect_secrets_output)
                    secret_settings.append(
                        f"{option_setting.get('Namespace', '')}/{option_setting.get('OptionName', '')}"
                    )

            if secret_settings:
                report.status = "FAIL"
                report.status_extended = (
                    f"Potential {'secrets' if len(secret_settings) > 1 else 'secret'} "
                    f"found in the configuration of Elastic Beanstalk environment "
                    f"{environment.name} -> {', '.join(secret_settings)}."
                )
                annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        return findings
