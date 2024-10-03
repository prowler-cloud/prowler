import zlib
from base64 import b64decode

from prowler.config.config import encoding_format_utf_8
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.logger import logger
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_launch_template_no_secrets(Check):
    def execute(self):
        findings = []
        secrets_ignore_patterns = ec2_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        for template in ec2_client.launch_templates:
            report = Check_Report_AWS(self.metadata())
            report.region = template.region
            report.resource_id = template.id
            report.resource_arn = template.arn
            report.resource_tags = template.tags

            versions_with_secrets = []

            for version in template.versions:
                if not version.template_data.user_data:
                    continue
                user_data = b64decode(version.template_data.user_data)

                try:
                    if user_data[0:2] == b"\x1f\x8b":  # GZIP magic number
                        user_data = zlib.decompress(
                            user_data, zlib.MAX_WBITS | 32
                        ).decode(encoding_format_utf_8)
                    else:
                        user_data = user_data.decode(encoding_format_utf_8)
                except UnicodeDecodeError as error:
                    logger.warning(
                        f"{template.region} -- Unable to decode User Data in EC2 Launch Template {template.name} version {version.version_number}: {error}"
                    )
                    continue
                except Exception as error:
                    logger.error(
                        f"{template.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue

                version_secrets = detect_secrets_scan(
                    data=user_data, excluded_secrets=secrets_ignore_patterns
                )

                if version_secrets:
                    versions_with_secrets.append(str(version.version_number))

            if len(versions_with_secrets) > 0:
                report.status = "FAIL"
                report.status_extended = f"Potential secret found in User Data for EC2 Launch Template {template.name} in template versions: {', '.join(versions_with_secrets)}."
            else:
                report.status = "PASS"
                report.status_extended = f"No secrets found in User Data of any version for EC2 Launch Template {template.name}."

            findings.append(report)

        return findings
