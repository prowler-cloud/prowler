from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.lightsail.lightsail_client import lightsail_client

default_php_blueprints = [
    "wordpress",
    "lamp",
    "nginx",
    "drupal",
    "joomla",
    "magento",
    "prestashop",
    "plesk",
    "cpanel",
]


class lightsail_instance_php_blueprint_updated(Check):
    def execute(self):
        findings = []
        php_blueprints = (
            lightsail_client.audit_config.get("lightsail_php_blueprints")
            or default_php_blueprints
        )

        for instance in lightsail_client.instances.values():
            blueprint = instance.blueprint_id.lower()
            if not any(blueprint.startswith(prefix) for prefix in php_blueprints):
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            report.status = "MANUAL"
            report.status_extended = f"Lightsail instance {instance.name} was created from the PHP blueprint '{instance.blueprint_id}'; the PHP runtime cannot be inspected through the API, verify over SSH that it runs a fixed release (8.2.35, 8.3.36, 8.4.27, 8.5.12 or newer); Bitnami-packaged blueprints bundle a PHP copy that apt never updates, so migrate them to the Lightsail-packaged blueprint or replace the bundled PHP with a package-managed one."

            findings.append(report)

        return findings
