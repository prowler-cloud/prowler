from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.directconnect.directconnect_client import (
    directconnect_client,
)


class directconnect_virtual_interface_redundancy(Check):
    def execute(self):
        findings = []
        for vgw in directconnect_client.vgws.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource_metadata=vgw)
            if len(vgw.vifs) < 2:
                report.status = "FAIL"
                report.status_extended = (
                    f"Virtual private gateway {vgw.id} only has one VIF."
                )
            elif len(vgw.connections) < 2:
                report.status = "FAIL"
                report.status_extended = f"Virtual private gateway {vgw.id} has more than 1 VIFs, but all the VIFs are on the same DX Connection."
            else:
                report.status = "PASS"
                report.status_extended = f"Virtual private gateway {vgw.id} has more than 1 VIFs and the VIFs are on more than one DX connection."

            findings.append(report)

        for dxgw in directconnect_client.dxgws.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource_metadata=dxgw)
            if len(dxgw.vifs) < 2:
                report.status = "FAIL"
                report.status_extended = (
                    f"Direct Connect gateway {dxgw.id} only has one VIF."
                )
            elif len(dxgw.connections) < 2:
                report.status = "FAIL"
                report.status_extended = f"Direct Connect gateway {dxgw.id} has more than 1 VIFs, but all the VIFs are on the same DX Connection."
            else:
                report.status = "PASS"
                report.status_extended = f"Direct Connect gateway {dxgw.id} has more than 1 VIFs and the VIFs are on more than one DX connection."

            findings.append(report)

        return findings
