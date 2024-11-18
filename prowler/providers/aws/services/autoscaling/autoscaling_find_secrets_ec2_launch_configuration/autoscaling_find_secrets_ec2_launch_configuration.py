import zlib
from base64 import b64decode

from prowler.config.config import encoding_format_utf_8
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.logger import logger
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.aws.services.autoscaling.autoscaling_client import (
    autoscaling_client,
)


class autoscaling_find_secrets_ec2_launch_configuration(Check):
    def execute(self):
        findings = []
        secrets_ignore_patterns = autoscaling_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        for (
            configuration_arn,
            configuration,
        ) in autoscaling_client.launch_configurations.items():
            report = Check_Report_AWS(self.metadata())
            report.region = configuration.region
            report.resource_id = configuration.name
            report.resource_arn = configuration_arn

            if configuration.user_data:
                user_data = b64decode(configuration.user_data)
                try:
                    if user_data[0:2] == b"\x1f\x8b":  # GZIP magic number
                        user_data = zlib.decompress(
                            user_data, zlib.MAX_WBITS | 32
                        ).decode(encoding_format_utf_8)
                    else:
                        user_data = user_data.decode(encoding_format_utf_8)
                except UnicodeDecodeError as error:
                    logger.warning(
                        f"{configuration.region} -- Unable to decode user data in autoscaling launch configuration {configuration.name}: {error}"
                    )
                    continue
                except Exception as error:
                    logger.error(
                        f"{configuration.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue

                has_secrets = detect_secrets_scan(
                    data=user_data, excluded_secrets=secrets_ignore_patterns
                )

                if has_secrets:
                    report.status = "FAIL"
                    report.status_extended = f"Potential secret found in autoscaling {configuration.name} User Data."
                else:
                    report.status = "PASS"
                    report.status_extended = f"No secrets found in autoscaling {configuration.name} User Data."
            else:
                report.status = "PASS"
                report.status_extended = f"No secrets found in autoscaling {configuration.name} since User Data is empty."

            findings.append(report)

        return findings
