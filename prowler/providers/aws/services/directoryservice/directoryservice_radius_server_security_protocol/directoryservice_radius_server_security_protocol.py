from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.directoryservice.directoryservice_client import (
    directoryservice_client,
)
from prowler.providers.aws.services.directoryservice.directoryservice_service import (
    AuthenticationProtocol,
)


class directoryservice_radius_server_security_protocol(Check):
    def execute(self):
        findings = []
        for directory in directoryservice_client.directories.values():
            if directory.radius_settings:
                report = Check_Report_AWS(self.metadata())
                report.region = directory.region
                report.resource_id = directory.id
                if (
                    directory.radius_settings.authentication_protocol
                    == AuthenticationProtocol.MS_CHAPv2
                ):
                    report.status = "PASS"
                    report.status_extended = f"Radius server of Directory {directory.id} have recommended security protocol for the Radius server"
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Radius server of Directory {directory.id} does not have recommended security protocol for the Radius server"

                findings.append(report)

        return findings
