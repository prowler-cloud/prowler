from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_endpoint_config_prod_variant_instances(Check):
    def execute(self):
        findings = []
        for endpoint_config in sagemaker_client.endpoint_configs.values():
            report = Check_Report_AWS(self.metadata())
            report.region = endpoint_config.region
            report.resource_id = endpoint_config.name
            report.resource_arn = endpoint_config.arn
            report.resource_tags = endpoint_config.tags
            report.status = "PASS"
            report.status_extended = f"Sagemaker Endpoint Config {endpoint_config.name} has all production variants with more than one initial instance."
            non_compliant_production_variants = []
            for production_variant in endpoint_config.production_variants:
                if production_variant.initial_instance_count <= 1:
                    non_compliant_production_variants.append(production_variant.name)

            if non_compliant_production_variants:
                report.status = "FAIL"
                report.status_extended = f"Sagemaker Endpoint Config {endpoint_config.name}'s production variants {', '.join(non_compliant_production_variants)} with less than two initial instance."

            findings.append(report)

        return findings
