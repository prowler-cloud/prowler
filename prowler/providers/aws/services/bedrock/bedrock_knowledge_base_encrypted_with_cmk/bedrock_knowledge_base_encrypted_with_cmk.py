from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)


class bedrock_knowledge_base_encrypted_with_cmk(Check):
    """Ensure Bedrock knowledge base data sources are encrypted with a CMK.

    One finding is reported per data source, because the key is configured on
    the data source rather than on the knowledge base.

    - PASS: The data source sets `serverSideEncryptionConfiguration.kmsKeyArn`,
      so the transient storage used during ingestion is encrypted with a key
      the account controls.
    - FAIL: No `kmsKeyArn` is set, so the ingested documents rest under an
      AWS-owned key the organization cannot audit, rotate, or revoke.
    - MANUAL: GetDataSource failed, so the key could not be retrieved and an
      absent value cannot be read as "no key"; or ListDataSources failed for the
      knowledge base, so its data sources are unknown; or ListKnowledgeBases
      failed for a region, so the region's knowledge bases are unknown.

    A knowledge base whose data sources could not be listed is reported against
    the knowledge base itself. Reporting nothing would drop it from the output
    entirely, which reads as "no data sources to flag" and is indistinguishable
    from a clean result.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for region, error in sorted(
            bedrock_agent_client.knowledge_bases_scan_errors.items()
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "knowledge-base/unknown"
            report.resource_arn = f"arn:{bedrock_agent_client.audited_partition}:bedrock:{region}:{bedrock_agent_client.audited_account}:knowledge-base/unknown"
            report.status = "MANUAL"
            report.status_extended = f"Bedrock knowledge bases could not be listed in region {region} ({error}); verify manually that every knowledge base data source uses a customer-managed KMS key."
            findings.append(report)

        for knowledge_base in bedrock_agent_client.knowledge_bases.values():
            if knowledge_base.data_sources_listed:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=knowledge_base)
            report.status = "MANUAL"
            reason = (
                f" ({knowledge_base.data_sources_error})"
                if knowledge_base.data_sources_error
                else ""
            )
            report.status_extended = f"Bedrock knowledge base {knowledge_base.name} data sources could not be listed in region {knowledge_base.region}{reason}; verify manually that each one uses a customer-managed KMS key."
            findings.append(report)

        for data_source in bedrock_agent_client.data_sources.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=data_source)
            knowledge_base = (
                data_source.knowledge_base_name or data_source.knowledge_base_id
            )

            if not data_source.detail_retrieved:
                report.status = "MANUAL"
                report.status_extended = f"Bedrock knowledge base {knowledge_base} data source {data_source.name} encryption configuration could not be retrieved in region {data_source.region}; verify manually that it uses a customer-managed KMS key."
            elif data_source.kms_key_arn:
                report.status = "PASS"
                report.status_extended = f"Bedrock knowledge base {knowledge_base} data source {data_source.name} is encrypted with a customer-managed KMS key in region {data_source.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock knowledge base {knowledge_base} data source {data_source.name} is not encrypted with a customer-managed KMS key in region {data_source.region}, so ingested documents rest under an AWS-owned key the organization cannot audit or revoke."
            findings.append(report)

        return findings
