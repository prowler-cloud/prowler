from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.acm.acm_client import acm_client
from prowler.providers.aws.services.elb.elb_client import elb_client


class elb_ssl_listeners_use_acm_certificate(Check):
    def execute(self):
        findings = []
        secure_protocols = ["SSL", "HTTPS"]
        for lb in elb_client.loadbalancers.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=lb)
            report.status = "PASS"
            report.status_extended = f"ELB {lb.name} HTTPS/SSL listeners are using certificates managed by ACM."
            for listener in lb.listeners:
                if (
                    listener.certificate_arn
                    and listener.protocol in secure_protocols
                    and acm_client.certificates[listener.certificate_arn].type
                    != "AMAZON_ISSUED"
                ):
                    report.status = "FAIL"
                    report.status_extended = f"ELB {lb.name} has HTTPS/SSL listeners that are using certificates not managed by ACM."
                    break

            findings.append(report)

        return findings
