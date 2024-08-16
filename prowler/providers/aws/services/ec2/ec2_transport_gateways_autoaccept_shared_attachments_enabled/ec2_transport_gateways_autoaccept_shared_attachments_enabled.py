import os
import tempfile
import zlib
from base64 import b64decode

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from prowler.config.config import encoding_format_utf_8
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_transport_gateways_autoaccept_shared_attachments_enabled(Check):
    def execute(self):
        findings = []
        for tgw in ec2_client.transit_gateways:
            report = Check_Report_AWS(self.metadata())
            report.region = tgw.region
            report.resource_id = tgw.id
            report.resource_arn = tgw.arn
            report.resource_tags = tgw.tags

            if tgw.auto_accept_shared_attachments:
                report.status = "FAIL"
                report.status_extended = (
                    f"Transit Gateway {tgw.id} in region {tgw.region} is configured to automatically accept shared VPC attachments."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Transit Gateway {tgw.id} in region {tgw.region} does not automatically accept shared VPC attachments."
                )

            findings.append(report)

        return findings
