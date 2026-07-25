import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.aws.services.appsync.appsync_client import appsync_client


class appsync_graphql_api_no_secrets_in_resolvers(Check):
    def execute(self):
        findings = []
        if appsync_client.graphql_apis:
            secrets_ignore_patterns = appsync_client.audit_config.get(
                "secrets_ignore_patterns", []
            )
            for api in appsync_client.graphql_apis.values():
                report = Check_Report_AWS(metadata=self.metadata(), resource=api)
                report.status = "PASS"
                report.status_extended = f"No secrets found in AppSync GraphQL API {api.name} resolvers or data sources."

                secrets_findings = []

                # Scan resolver mapping templates
                for resolver in api.resolvers:
                    # Scan request mapping template
                    if resolver.request_mapping_template:
                        request_secrets = detect_secrets_scan(
                            data=resolver.request_mapping_template,
                            excluded_secrets=secrets_ignore_patterns,
                            detect_secrets_plugins=appsync_client.audit_config.get(
                                "detect_secrets_plugins"
                            ),
                        )
                        if request_secrets:
                            secrets_string = ", ".join(
                                [
                                    f"{secret['type']} on line {secret['line_number']}"
                                    for secret in request_secrets
                                ]
                            )
                            secrets_findings.append(
                                f"Resolver {resolver.type_name}.{resolver.field_name} (request template): {secrets_string}"
                            )

                    # Scan response mapping template
                    if resolver.response_mapping_template:
                        response_secrets = detect_secrets_scan(
                            data=resolver.response_mapping_template,
                            excluded_secrets=secrets_ignore_patterns,
                            detect_secrets_plugins=appsync_client.audit_config.get(
                                "detect_secrets_plugins"
                            ),
                        )
                        if response_secrets:
                            secrets_string = ", ".join(
                                [
                                    f"{secret['type']} on line {secret['line_number']}"
                                    for secret in response_secrets
                                ]
                            )
                            secrets_findings.append(
                                f"Resolver {resolver.type_name}.{resolver.field_name} (response template): {secrets_string}"
                            )

                # Scan data source configurations
                for data_source in api.data_sources:
                    # Combine all config dictionaries into a single string for scanning
                    configs_to_scan = {
                        "dynamodb_config": data_source.dynamodb_config,
                        "lambda_config": data_source.lambda_config,
                        "elasticsearch_config": data_source.elasticsearch_config,
                        "opensearchservice_config": data_source.opensearchservice_config,
                        "http_config": data_source.http_config,
                        "relational_database_config": data_source.relational_database_config,
                        "event_bridge_config": data_source.event_bridge_config,
                    }

                    for config_name, config_data in configs_to_scan.items():
                        if config_data:
                            # Convert config to JSON string for scanning
                            config_string = json.dumps(config_data)
                            config_secrets = detect_secrets_scan(
                                data=config_string,
                                excluded_secrets=secrets_ignore_patterns,
                                detect_secrets_plugins=appsync_client.audit_config.get(
                                    "detect_secrets_plugins"
                                ),
                            )
                            if config_secrets:
                                secrets_string = ", ".join(
                                    [
                                        f"{secret['type']} on line {secret['line_number']}"
                                        for secret in config_secrets
                                    ]
                                )
                                secrets_findings.append(
                                    f"DataSource {data_source.name} ({config_name}): {secrets_string}"
                                )

                if secrets_findings:
                    final_output_string = "; ".join(secrets_findings)
                    report.status = "FAIL"
                    report.status_extended = f"Potential {'secrets' if len(secrets_findings) > 1 else 'secret'} found in AppSync GraphQL API {api.name} -> {final_output_string}."

                findings.append(report)

        return findings
