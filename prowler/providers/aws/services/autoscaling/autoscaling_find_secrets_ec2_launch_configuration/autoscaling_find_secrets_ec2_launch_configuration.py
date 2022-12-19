import os
import tempfile
from base64 import b64decode

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.autoscaling.autoscaling_client import (
    autoscaling_client,
)


class autoscaling_find_secrets_ec2_launch_configuration(Check):
    def execute(self):
        findings = []
        for configuration in autoscaling_client.launch_configurations:
            report = Check_Report_AWS(self.metadata())
            report.region = configuration.region
            report.resource_id = configuration.name
            report.resource_arn = configuration.arn

            if configuration.user_data:
                temp_user_data_file = tempfile.NamedTemporaryFile(delete=False)
                user_data = b64decode(configuration.user_data).decode("utf-8")

                temp_user_data_file.write(
                    bytes(user_data, encoding="raw_unicode_escape")
                )
                temp_user_data_file.close()
                secrets = SecretsCollection()
                with default_settings():
                    secrets.scan_file(temp_user_data_file.name)

                if secrets.json():
                    report.status = "FAIL"
                    report.status_extended = f"Potential secret found in autoscaling {configuration.name} User Data."
                else:
                    report.status = "PASS"
                    report.status_extended = f"No secrets found in autoscaling {configuration.name} User Data."

                os.remove(temp_user_data_file.name)
            else:
                report.status = "PASS"
                report.status_extended = f"No secrets found in autoscaling {configuration.name} since User Data is empty."

            findings.append(report)

        return findings
