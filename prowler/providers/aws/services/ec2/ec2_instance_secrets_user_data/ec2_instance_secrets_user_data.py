import os
import tempfile
from base64 import b64decode

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_secrets_user_data(Check):
    def execute(self):
        findings = []
        for instance in ec2_client.instances:
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id

            if instance.user_data:
                temp_user_data_file = tempfile.NamedTemporaryFile(delete=False)
                user_data = b64decode(instance.user_data).decode("utf-8")

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
