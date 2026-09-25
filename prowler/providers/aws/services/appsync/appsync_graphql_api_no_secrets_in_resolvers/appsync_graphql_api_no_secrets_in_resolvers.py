import json
from collections import defaultdict

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.appsync.appsync_client import appsync_client


class appsync_graphql_api_no_secrets_in_resolvers(Check):
    def execute(self):
        findings = []
        if not appsync_client.graphql_apis:
            return findings

        secrets_ignore_patterns = appsync_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = appsync_client.audit_config.get("secrets_validate", False)

        # Phase 1: Collect - Build API list and generate payloads
        # Use a lazy generator to yield (key, payload) tuples for batch scanning.
        # Keys are (api_index, component_type, component_id) tuples to map findings
        # back to specific APIs, resolvers, and data sources.
        apis_list = list(appsync_client.graphql_apis.values())

        def resolver_and_datasource_payloads():
            for api_index, api in enumerate(apis_list):

                # Yield resolver mapping templates
                for resolver in api.resolvers:
                    resolver_id = f"{resolver.type_name}.{resolver.field_name}"

                    if resolver.request_mapping_template:
                        yield (
                            api_index,
                            "resolver",
                            f"{resolver_id} (request template)",
                        ), resolver.request_mapping_template

                    if resolver.response_mapping_template:
                        yield (
                            api_index,
                            "resolver",
                            f"{resolver_id} (response template)",
                        ), resolver.response_mapping_template

                # Yield data source configurations
                for data_source in api.data_sources:
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
                            yield (
                                api_index,
                                "datasource",
                                f"{data_source.name} ({config_name})",
                            ), json.dumps(config_data)

        # Phase 2: Batch - Execute single batched Kingfisher scan
        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                resolver_and_datasource_payloads(),
                excluded_secrets=secrets_ignore_patterns,
                validate=validate,
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        # Handle scan failures - report MANUAL for all APIs
        if scan_error:
            for api in appsync_client.graphql_apis.values():
                report = Check_Report_AWS(metadata=self.metadata(), resource=api)
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan AppSync GraphQL API {api.name} resolvers and "
                    f"data sources for secrets: {scan_error}; manual review is required."
                )
                findings.append(report)
            return findings

        # Phase 3: Report - Map findings back to APIs and generate reports
        # Group findings by API index
        findings_by_api = defaultdict(dict)
        for (api_index, component_type, component_id), component_findings in batch_results.items():
            if component_type not in findings_by_api[api_index]:
                findings_by_api[api_index][component_type] = {}
            findings_by_api[api_index][component_type][component_id] = component_findings

        # Generate one report per API
        for api_index, api in enumerate(apis_list):
            report = Check_Report_AWS(metadata=self.metadata(), resource=api)
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in AppSync GraphQL API {api.name} resolvers or data sources."
            )

            api_findings = findings_by_api.get(api_index, {})
            if api_findings:
                all_secrets = []
                secrets_findings = []

                # Process resolver findings
                for resolver_id, resolver_findings in api_findings.get("resolver", {}).items():
                    all_secrets.extend(resolver_findings)
                    secrets_string = ", ".join(
                        f"{secret['type']} on line {secret['line_number']}"
                        for secret in resolver_findings
                    )
                    secrets_findings.append(f"Resolver {resolver_id}: {secrets_string}")

                # Process data source findings
                for datasource_id, datasource_findings in api_findings.get("datasource", {}).items():
                    all_secrets.extend(datasource_findings)
                    secrets_string = ", ".join(
                        f"{secret['type']} on line {secret['line_number']}"
                        for secret in datasource_findings
                    )
                    secrets_findings.append(f"DataSource {datasource_id}: {secrets_string}")

                if secrets_findings:
                    final_output_string = "; ".join(secrets_findings)
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Potential {'secrets' if len(secrets_findings) > 1 else 'secret'} "
                        f"found in AppSync GraphQL API {api.name} -> {final_output_string}."
                    )
                    # Escalate severity to CRITICAL if secrets are verified
                    annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        return findings
