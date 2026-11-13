from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearchserverless.opensearchserverless_client import (
    opensearchserverless_client,
)


class opensearchserverless_collection_not_publicly_accessible(Check):
    """Ensure OpenSearch Serverless collections are not reachable from the internet.

    A collection is evaluated against the network policy rules that cover it:
    - FAIL if any rule that covers it for sure allows public access.
    - MANUAL if a rule that might cover it allows public access, if not all
      network policies of its region could be read, or if no rule covers it
      for sure, because public exposure cannot be ruled out.
    - PASS if all network policies were read, at least one rule covers it for
      sure, and none of the rules that cover it allows public access.

    Regions whose collections could not be fully listed get one MANUAL
    finding each, since collections missing from the inventory cannot be
    evaluated.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports, one per collection, plus one MANUAL report per
            region whose collections could not be fully listed.
        """
        findings = []
        for collection in opensearchserverless_client.collections.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=collection)

            public_rules = [
                rule for rule in collection.network_rules if rule.allow_from_public
            ]
            doubtful_public_rules = [
                rule
                for rule in collection.doubtful_network_rules
                if rule.allow_from_public
            ]

            if public_rules:
                endpoints = sorted({rule.resource_type for rule in public_rules})
                policies = sorted({rule.policy_name for rule in public_rules})
                report.status = "FAIL"
                report.status_extended = (
                    f"OpenSearch Serverless collection {collection.name} is publicly "
                    f"accessible through its {' and '.join(endpoints)} endpoint "
                    f"by network policy {', '.join(policies)}."
                )
            elif doubtful_public_rules:
                policies = sorted({rule.policy_name for rule in doubtful_public_rules})
                report.status = "MANUAL"
                report.status_extended = (
                    f"OpenSearch Serverless collection {collection.name} might be "
                    f"publicly accessible: network policy {', '.join(policies)} "
                    "allows public access with a resource pattern whose coverage "
                    "could not be determined."
                )
            elif not collection.network_policies_complete:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not evaluate public access for OpenSearch Serverless "
                    f"collection {collection.name}: not all network policies in "
                    f"{collection.region} could be read. Verify that "
                    "aoss:ListSecurityPolicies and aoss:GetSecurityPolicy are "
                    "granted to the scanning identity."
                )
            elif collection.network_rules:
                report.status = "PASS"
                report.status_extended = (
                    f"OpenSearch Serverless collection {collection.name} is not "
                    "publicly accessible."
                )
            else:
                report.status = "MANUAL"
                report.status_extended = (
                    f"OpenSearch Serverless collection {collection.name} is not "
                    "covered by any network policy rule that could be evaluated; "
                    "review its network access manually."
                )

            findings.append(report)

        for region in sorted(
            opensearchserverless_client.collections_listing_failed_regions
        ):
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.region = region
            report.resource_id = "unknown"
            report.resource_arn = opensearchserverless_client.get_unknown_arn(
                region=region, resource_type="collection"
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Could not evaluate public access for OpenSearch Serverless "
                f"collections in {region}: the collections could not be fully "
                "listed. Verify that aoss:ListCollections is granted to the "
                "scanning identity."
            )
            findings.append(report)

        return findings
