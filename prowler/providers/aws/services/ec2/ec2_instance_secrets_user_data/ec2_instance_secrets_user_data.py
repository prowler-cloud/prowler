import os
import tempfile
import zlib
from base64 import b64decode

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_secrets_user_data(Check):
    def execute(self):
        findings = []
        for instance in ec2_client.instances:
            if instance.state != "terminated":
                report = Check_Report_AWS(self.metadata())
                report.region = instance.region
                report.resource_id = instance.id
                report.resource_arn = instance.arn
                report.resource_tags = instance.tags
                if instance.user_data:
                    temp_user_data_file = tempfile.NamedTemporaryFile(delete=False)
                    user_data = b64decode(instance.user_data)
                    if user_data[0:2] == b"\x1f\x8b":  # GZIP magic number
                        user_data = zlib.decompress(
                            user_data, zlib.MAX_WBITS | 32
                        ).decode("utf-8")
                    else:
                        user_data = user_data.decode("utf-8")

                    temp_user_data_file.write(
                        bytes(user_data, encoding="raw_unicode_escape")
                    )
                    temp_user_data_file.close()
                    secrets = SecretsCollection()
                    with default_settings():
                        secrets.scan_file(temp_user_data_file.name)

                    if secrets.json():
                        report.status = "FAIL"
                        report.status_extended = f"Potential secret found in EC2 instance {instance.id} User Data."
                    else:
                        report.status = "PASS"
                        report.status_extended = (
                            f"No secrets found in EC2 instance {instance.id} User Data."
                        )

                    os.remove(temp_user_data_file.name)
                else:
                    report.status = "PASS"
                    report.status_extended = f"No secrets found in EC2 instance {instance.id} since User Data is empty."

                findings.append(report)

        return findings
