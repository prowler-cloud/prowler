from prowler.lib.logger import logger
from prowler.lib.check.models import Check, Check_Report_OpenNebula
from prowler.providers.opennebula.services.template.template_client import template_client

class template_has_embedded_credentials(Check):
    def execute(self):
        findings = []
        logger.info("Checking for OpenNebula templates with embedded credentials or secrets in CONTEXT...")

        sensitive_keys = ["PASSWORD", "PASSWORD_BASE64", "SSH_PUBLIC_KEY", "TOKEN", "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID"]

        for template in template_client.templates:
            report = Check_Report_OpenNebula(
                metadata=self.metadata(),
                resource=template.name,
            )
            embedded_secrets = []

            for key in sensitive_keys:
                if key in template.context:
                    value = template.context[key]
                    if value and not value.startswith("$"):
                        embedded_secrets.append(key)

            if embedded_secrets:
                report.status = "FAIL"
                report.status_extended = (
                    f"Template {template.name} has embedded sensitive fields in CONTEXT: {', '.join(embedded_secrets)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Template {template.name} has no embedded credentials in CONTEXT."
                )

            findings.append(report)

        return findings
