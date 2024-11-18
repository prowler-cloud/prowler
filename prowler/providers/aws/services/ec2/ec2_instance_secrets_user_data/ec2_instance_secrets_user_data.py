import zlib
from base64 import b64decode

from prowler.config.config import encoding_format_utf_8
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.logger import logger
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_secrets_user_data(Check):
    def execute(self):
        findings = []
        secrets_ignore_patterns = ec2_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        for instance in ec2_client.instances:
            if instance.state != "terminated":
                report = Check_Report_AWS(self.metadata())
                report.region = instance.region
                report.resource_id = instance.id
                report.resource_arn = instance.arn
                report.resource_tags = instance.tags
                if instance.user_data:
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
                        continue
                    except Exception as error:
                        logger.error(
                            f"{instance.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                        continue
                    detect_secrets_output = detect_secrets_scan(
                        data=user_data, excluded_secrets=secrets_ignore_patterns
                    )
                    if detect_secrets_output:
                        secrets_string = ", ".join(
                            [
                                f"{secret['type']} on line {secret['line_number']}"
                                for secret in detect_secrets_output
                            ]
                        )
                        report.status = "FAIL"
                        report.status_extended = f"Potential secret found in EC2 instance {instance.id} User Data -> {secrets_string}."

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
