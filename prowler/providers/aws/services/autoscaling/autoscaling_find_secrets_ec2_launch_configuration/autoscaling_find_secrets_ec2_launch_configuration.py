import zlib
from base64 import b64decode

from prowler.config.config import encoding_format_utf_8
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.logger import logger
from prowler.lib.utils.utils import (
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.autoscaling.autoscaling_client import (
    autoscaling_client,
)


class autoscaling_find_secrets_ec2_launch_configuration(Check):
    def execute(self):
        findings = []
        secrets_ignore_patterns = autoscaling_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = autoscaling_client.audit_config.get("secrets_validate", False)
        configurations = list(autoscaling_client.launch_configurations.values())

        # Collect the decoded User Data of each launch configuration and scan it
        # all in batched Kingfisher invocations instead of one subprocess each.
        # Configurations whose User Data cannot be decoded are skipped (no report),
        # matching the original per-resource behavior.
        skipped = set()

        def payloads():
            for index, configuration in enumerate(configurations):
                if not configuration.user_data:
                    continue
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
                    skipped.add(index)
                    continue
                except Exception as error:
                    logger.error(
                        f"{configuration.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    skipped.add(index)
                    continue
                yield index, user_data

        batch_results = detect_secrets_scan_batch(
            payloads(), excluded_secrets=secrets_ignore_patterns, validate=validate
        )

        for index, configuration in enumerate(configurations):
            if index in skipped:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=configuration)

            if configuration.user_data:
                has_secrets = batch_results.get(index)
                if has_secrets:
                    report.status = "FAIL"
                    report.status_extended = f"Potential secret found in autoscaling {configuration.name} User Data."
                    annotate_verified_secrets(report, has_secrets)
                else:
                    report.status = "PASS"
                    report.status_extended = f"No secrets found in autoscaling {configuration.name} User Data."
            else:
                report.status = "PASS"
                report.status_extended = f"No secrets found in autoscaling {configuration.name} since User Data is empty."

            findings.append(report)

        return findings
