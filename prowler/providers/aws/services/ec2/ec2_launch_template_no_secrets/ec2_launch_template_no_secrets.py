import os
import tempfile
import zlib
from base64 import b64decode

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from prowler.config.config import enconding_format_utf_8
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_launch_template_no_secrets(Check):
    def execute(self):
        findings = []
        for template in ec2_client.launch_templates:
            report = Check_Report_AWS(self.metadata())
            report.region = template.region
            report.resource_id = template.id
            report.resource_arn = template.arn

            versions_with_secrets = []

            for version in template.versions:
                if "UserData" not in version.template_data:
                    continue

                temp_user_data_file = tempfile.NamedTemporaryFile(delete=False)
                user_data = b64decode(version.template_data["UserData"])

                if user_data[0:2] == b"\x1f\x8b":  # GZIP magic number
                    user_data = zlib.decompress(user_data, zlib.MAX_WBITS | 32).decode(
                        enconding_format_utf_8
                    )
                else:
                    user_data = user_data.decode(enconding_format_utf_8)

                temp_user_data_file.write(
                    bytes(user_data, encoding="raw_unicode_escape")
                )
                temp_user_data_file.close()
                secrets = SecretsCollection()
                with default_settings():
                    secrets.scan_file(temp_user_data_file.name)

                if secrets.json():
                    versions_with_secrets.append(str(version.version_number))

                os.remove(temp_user_data_file.name)

            if len(versions_with_secrets) > 0:
                report.status = "FAIL"
                report.status_extended = f"Potential secret found in User Data for EC2 Launch Template {template.name} in template versions: {', '.join(versions_with_secrets)}."
            else:
                report.status = "PASS"
                report.status_extended = f"No secrets found in User Data of any version for EC2 Launch Template {template.name}."

            findings.append(report)

        return findings
