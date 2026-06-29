import zlib
from base64 import b64decode

from prowler.config.config import encoding_format_utf_8
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.logger import logger
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_secrets_user_data(Check):
    def execute(self):
        findings = []
        secrets_ignore_patterns = ec2_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = ec2_client.audit_config.get("secrets_validate", False)
        instances = list(ec2_client.instances)

        # Collect the decoded User Data of each non-terminated instance and scan
        # it all in batched Kingfisher invocations instead of one subprocess each.
        # Instances whose User Data cannot be decoded are undecodable (no report),
        # matching the original per-resource behavior.
        undecodable = set()

        def payloads():
            for index, instance in enumerate(instances):
                if instance.state == "terminated" or not instance.user_data:
                    continue
                user_data = b64decode(instance.user_data)
                try:
                    if user_data[0:2] == b"\x1f\x8b":  # GZIP magic number
                        user_data = zlib.decompress(
                            user_data, zlib.MAX_WBITS | 32
                        ).decode(encoding_format_utf_8)
                    else:
                        user_data = user_data.decode(encoding_format_utf_8)
                except UnicodeDecodeError as error:
                    logger.warning(
                        f"{instance.region} -- Unable to decode user data in EC2 instance {instance.id}: {error}"
                    )
                    undecodable.add(index)
                    continue
                except Exception as error:
                    logger.error(
                        f"{instance.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    undecodable.add(index)
                    continue
                yield index, user_data

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(), excluded_secrets=secrets_ignore_patterns, validate=validate
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for index, instance in enumerate(instances):
            if instance.state == "terminated":
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            if scan_error and instance.user_data:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan EC2 instance {instance.id} User Data for "
                    f"secrets: {scan_error}; manual review is required."
                )
                findings.append(report)
                continue
            if index in undecodable:
                report.status = "MANUAL"
                report.status_extended = f"Could not decode User Data for EC2 instance {instance.id}; manual review is required to scan for secrets."
            elif instance.user_data:
                detect_secrets_output = batch_results.get(index)
                if detect_secrets_output:
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} on line {secret['line_number']}"
                            for secret in detect_secrets_output
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Potential secret found in EC2 instance {instance.id} User Data -> {secrets_string}."
                    annotate_verified_secrets(report, detect_secrets_output)
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"No secrets found in EC2 instance {instance.id} User Data."
                    )
            else:
                report.status = "PASS"
                report.status_extended = f"No secrets found in EC2 instance {instance.id} since User Data is empty."

            findings.append(report)

        return findings
