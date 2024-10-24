from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.directconnect.directconnect_client import (
    directconnect_client,
)


class directconnect_virtual_interface_redundancy(Check):
    def execute(self):
        findings = []
        for vgw in directconnect_client.vgws.values():
            if vgw.id:
                report = Check_Report_AWS(self.metadata())
                report.resource_arn = vgw.id
                report.region = vgw.region
                report.resource_id = vgw.id
                if len(vgw.vifs) < 2:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"There is only one VIF for the virtual gateway {vgw.id}."
                    )
                elif len(vgw.connections) < 2:
                    report.status = "FAIL"
                    report.status_extended = f"There are more than 1 VIFs for the virtual gateway {vgw.id}, but all the VIFs are on the same DX Connection."
                else:
                    report.status = "PASS"
                    report.status_extended = f"There are more than 1 VIFs for the virtual gateway {vgw.id}, and the VIFs are on more than one DX connection."

                findings.append(report)

        for dxgw in directconnect_client.dxgws.values():
            if dxgw.id:
                report = Check_Report_AWS(self.metadata())
                report.region = dxgw.region
                report.resource_arn = dxgw.id
                report.resource_id = dxgw.id
                if len(dxgw.vifs) < 2:
                    report.status = "FAIL"
                    report.status_extended = f"There is only one VIF for the direct connect gateway {dxgw.id}."
                elif len(dxgw.connections) < 2:
                    report.status = "FAIL"
                    report.status_extended = f"There are more than 1 VIFs for direct connect gateway {dxgw.id}, but all the VIFs are on the same DX Connection."
                else:
                    report.status = "PASS"
                    report.status_extended = f"There are more than 1 VIFs for the direct connect gateway {dxgw.id}, and the VIFs are on more than one DX connection."

                findings.append(report)

        return findings
