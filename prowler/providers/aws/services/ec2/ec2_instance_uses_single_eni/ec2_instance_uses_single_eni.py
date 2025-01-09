from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_uses_single_eni(Check):
    def execute(self):
        findings = []
        for instance in ec2_client.instances:
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = instance.arn
            report.resource_tags = instance.tags
            eni_types = {"efa": [], "interface": [], "trunk": []}
            if not instance.network_interfaces:
                report.status = "PASS"
                report.status_extended = (
                    f"EC2 Instance {instance.id} has no network interfaces attached."
                )
            else:
                for eni_id in instance.network_interfaces:
                    if (
                        eni_id in ec2_client.network_interfaces
                        and ec2_client.network_interfaces[eni_id].type in eni_types
                    ):
                        eni_types[ec2_client.network_interfaces[eni_id].type].append(
                            eni_id
                        )

                message_status_extended = ""
                if (
                    len(eni_types["efa"])
                    + len(eni_types["interface"])
                    + len(eni_types["trunk"])
                    > 1
                ):
                    report.status = "FAIL"
                    message_status_extended = (
                        f"EC2 Instance {instance.id} uses multiple ENIs: ("
                    )
                else:
                    report.status = "PASS"
                    message_status_extended = (
                        f"EC2 Instance {instance.id} uses only one ENI: ("
                    )

                if eni_types["efa"]:
                    message_status_extended += f" EFAs: {eni_types['efa']}"
                if eni_types["interface"]:
                    message_status_extended += f" Interfaces: {eni_types['interface']}"
                if eni_types["trunk"]:
                    message_status_extended += f" Trunks: {eni_types['trunk']}"
                report.status_extended = message_status_extended + " )."

            findings.append(report)

        return findings
