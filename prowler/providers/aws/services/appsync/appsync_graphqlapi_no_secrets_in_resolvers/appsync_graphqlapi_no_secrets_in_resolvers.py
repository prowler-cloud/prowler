import json
from collections import defaultdict

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.appsync.appsync_client import appsync_client


class appsync_graphqlapi_no_secrets_in_resolvers(Check):
    """Check for secrets in AppSync resolvers and data sources.

    Scans request/response mapping templates of every resolver and the
    serialized configuration of every data source attached to each AppSync
    GraphQL API. Hardcoded API keys, database credentials, tokens and other
    embedded secrets are detected using Prowler's batched Kingfisher secret
    scanner.

    - PASS: No secrets are found in any resolver mapping template or data
      source configuration for this GraphQL API.
    - FAIL: At least one secret is found in a resolver mapping template or
      data source configuration for this GraphQL API.
    - MANUAL: The secret scanner failed (e.g. Kingfisher error) but the API
      has resolvers or data sources - manual review is required.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the AppSync secrets-in-resolvers check.

        Builds one scan payload per resolver mapping template and per data
        source configuration, batches them into a single Kingfisher invocation,
        then maps the results back to per-API findings keyed by API ARN.

        Returns:
            list[Check_Report_AWS]: One report per AppSync GraphQL API.
        """
        findings = []
        if not appsync_client.graphql_apis:
            return findings

        secrets_ignore_patterns = appsync_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = appsync_client.audit_config.get("secrets_validate", False)

        # Build payloads to scan. Each payload is keyed by (api_arn,
        # resource_kind, resource_name) so findings can be grouped back per
        # GraphQL API using the ARN (stable across ordering changes).
        def payloads():
            for api in appsync_client.graphql_apis.values():
                # Scan resolvers
                for resolver in api.resolvers:
                    if resolver.request_mapping_template:
                        yield (
                            api.arn,
                            "resolver",
                            f"{resolver.type_name}.{resolver.field_name}.requestMappingTemplate",
                        ), resolver.request_mapping_template
                    if resolver.response_mapping_template:
                        yield (
                            api.arn,
                            "resolver",
                            f"{resolver.type_name}.{resolver.field_name}.responseMappingTemplate",
                        ), resolver.response_mapping_template

                # Scan data sources - serialize their configuration for scanning
                for data_source in api.data_sources:
                    # Build a text representation of the data source config
                    config_parts = []
                    if data_source.description:
                        config_parts.append(
                            f"description: {data_source.description}"
                        )
                    if data_source.lambda_config:
                        config_parts.append(
                            json.dumps(data_source.lambda_config, sort_keys=True)
                        )
                    if data_source.dynamodb_config:
                        config_parts.append(
                            json.dumps(data_source.dynamodb_config, sort_keys=True)
                        )
                    if data_source.elasticsearch_config:
                        config_parts.append(
                            json.dumps(data_source.elasticsearch_config, sort_keys=True)
                        )
                    if data_source.http_config:
                        config_parts.append(
                            json.dumps(data_source.http_config, sort_keys=True)
                        )
                    if data_source.relational_database_config:
                        config_parts.append(
                            json.dumps(
                                data_source.relational_database_config, sort_keys=True
                            )
                        )
                    if config_parts:
                        yield (api.arn, "data_source", data_source.name), "\n".join(
                            config_parts
                        )

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(),
                excluded_secrets=secrets_ignore_patterns,
                validate=validate,
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        # Group findings by API ARN once, then look up per API in O(1).
        findings_by_arn = defaultdict(list)
        for (api_arn, resource_kind, resource_name), secrets_list in batch_results.items():
            findings_by_arn[api_arn].append(
                (resource_kind, resource_name, secrets_list)
            )

        for api in appsync_client.graphql_apis.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=api)
            report.resource_id = api.name
            report.resource_arn = api.arn
            report.resource_tags = api.tags
            report.region = api.region
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in AppSync GraphQL API {api.name} "
                f"resolver mapping templates or data sources."
            )

            if scan_error:
                # If there are resolvers or data sources and scan failed,
                # report MANUAL for this API
                if api.resolvers or api.data_sources:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not scan AppSync GraphQL API {api.name} resolvers "
                        f"and data sources for secrets: {scan_error}; "
                        f"manual review is required."
                    )
                findings.append(report)
                continue

            api_findings = findings_by_arn.get(api.arn, [])
            if api_findings:
                all_secrets = []
                secrets_findings = []
                for (
                    resource_kind,
                    resource_name,
                    secrets_list,
                ) in api_findings:
                    all_secrets.extend(secrets_list)
                    secrets_string = ", ".join(
                        f"{secret['type']} on line {secret['line_number']}"
                        for secret in secrets_list
                    )
                    secrets_findings.append(
                        f"{resource_kind} {resource_name}: {secrets_string}"
                    )

                final_output_string = "; ".join(secrets_findings)
                report.status = "FAIL"
                report.status_extended = (
                    f"Potential {'secrets' if len(all_secrets) > 1 else 'secret'} "
                    f"found in AppSync GraphQL API {api.name} -> {final_output_string}."
                )
                annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        return findings
