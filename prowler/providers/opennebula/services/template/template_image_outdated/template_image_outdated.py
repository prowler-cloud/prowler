from prowler.lib.logger import logger
from prowler.lib.check.models import Check, Check_Report_OpenNebula
from prowler.providers.opennebula.services.template.template_client import template_client

class template_image_outdated(Check):
    def execute(self):
        findings = []
        logger.info("Checking for OpenNebula templates based on outdated operating systems or images...")

        legacy_indicators = [
            "centos 6", "centos6", "ubuntu 14", "ubuntu14", "ubuntu 16", "ubuntu16",
            "windows server 2008", "windows 2008", "debian 8", "debian8", "rhel 6", "rhel6"
        ]

        for template in template_client.templates:
            report = Check_Report_OpenNebula(
                metadata=self.metadata(),
                resource=template.name,
            )
            signs_of_legacy = []

            os_attributes = template.os or {}
            for value in os_attributes.values():
                if value and any(indicator in value.lower() for indicator in legacy_indicators):
                    signs_of_legacy.append(value)

            if not signs_of_legacy:
                if any(indicator in template.name.lower() for indicator in legacy_indicators):
                    signs_of_legacy.append(template.name)

            if signs_of_legacy:
                report.status = "FAIL"
                report.status_extended = (
                    f"Template {template.name} appears based on outdated OS/image: {', '.join(signs_of_legacy)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Template {template.name} is not based on a known outdated OS/image."
                )

            findings.append(report)

        return findings
