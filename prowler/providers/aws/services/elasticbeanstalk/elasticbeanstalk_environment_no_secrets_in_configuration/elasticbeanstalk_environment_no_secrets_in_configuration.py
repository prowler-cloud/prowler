from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.elasticbeanstalk import elasticbeanstalk_client

class elasticbeanstalk_environment_no_secrets_in_configuration(Check):
    def execute(self) :
        findings = []
        secrets_ignore_patterns = elasticbeanstalk_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = elasticbeanstalk_client.audit_config.get("secrets_validate", False)

        def payloads():
            for environment in elasticbeanstalk_client.environments.values():
                for option_setting in environment.option_settings:
                    value = option_setting.get("Value")
                    if not value:
                        continue
                    yield((environment.arn, option_setting["Namespace"], option_setting["OptionName"]), value)

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
            for environment in elasticbeanstalk_client.environments.values():
                report = Check_Report_AWS(metadata=self.metadata(), resource=environment)
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan Elastic BeanStalk environment configuration for "
                    f"{environment.name} environment for secrets: {scan_error}; "
                    f"manual review is required."
                )
                findings.append(report)
            return findings

        for environment in elasticbeanstalk_client.environments.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=environment)
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Elastic BeanStalk environment configuration for {environment.name} environment."
            )
            detected_secret_settings = []
            all_secrets = []
            for option_setting in environment.option_settings:
                detect_secret_outputs = batch_results.get((environment.arn, option_setting["Namespace"], option_setting["OptionName"]))
                 
                if detect_secret_outputs:
                    detected_secret_settings.append((option_setting["Namespace"], option_setting["OptionName"]))
                    all_secrets.extend(detect_secret_outputs)
                
            if detected_secret_settings:
                secret_setting = "; ".join(
                    f"Namespace: {namespace}, OptionName: {option_name}" for namespace, option_name in detected_secret_settings
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"Potential "
                    f"{'secrets' if len(detected_secret_settings) > 1 else 'secret'} "
                    f"found in Elastic BeanStalk environment configuration for "
                    f"{environment.name} environment -> {secret_setting}."
                )
                annotate_verified_secrets(report, all_secrets)

            findings.append(report)
            
        return findings