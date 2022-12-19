from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_insecure_ssl_ciphers(Check):
    def execute(self):
        findings = []
        secure_ssl_policies = [
            "ELBSecurityPolicy-TLS-1-2-2017-01",
            "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
            "ELBSecurityPolicy-FS-1-2-2019-08",
            "ELBSecurityPolicy-FS-1-2-Res-2019-08",
            "ELBSecurityPolicy-FS-1-2-Res-2020-10",
            "ELBSecurityPolicy-TLS13-1-2-2021-06",
            "ELBSecurityPolicy-TLS13-1-3-2021-06",
            "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
            "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
            "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
        ]
        for lb in elbv2_client.loadbalancersv2:
            report = Check_Report_AWS(self.metadata())
            report.region = lb.region
            report.resource_id = lb.name
            report.resource_arn = lb.arn
            report.status = "PASS"
            report.status_extended = (
                f"ELBv2 {lb.name} has not insecure SSL protocols or ciphers."
            )
            for listener in lb.listeners:
                if (
                    listener.protocol == "HTTPS"
                    and listener.ssl_policy not in secure_ssl_policies
                ):
                    report.status = "FAIL"
                    report.status_extended = f"ELBv2 {lb.name} has listeners with insecure SSL protocols or ciphers."

            findings.append(report)

        return findings
