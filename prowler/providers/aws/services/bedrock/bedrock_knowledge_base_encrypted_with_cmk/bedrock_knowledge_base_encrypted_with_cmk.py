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
      absent value cannot be read as "no key".
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for data_source in bedrock_agent_client.data_sources.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=data_source)
            knowledge_base = (
                data_source.knowledge_base_name or data_source.knowledge_base_id
            )

            if not data_source.detail_retrieved:
                # GetDataSource failed (permissions, throttling, transient
                # error). Do not assert compliance from an absent answer.
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
