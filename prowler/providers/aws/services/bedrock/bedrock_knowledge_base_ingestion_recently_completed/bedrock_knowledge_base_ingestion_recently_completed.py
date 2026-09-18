from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)


class bedrock_knowledge_base_ingestion_recently_completed(Check):
    """Ensure Bedrock knowledge base data sources have recently ingested successfully.

    One finding is reported per data source, because ingestion jobs run per data source.

    - PASS: The latest successful (COMPLETE) ingestion job finished within the configured
      window (``bedrock_knowledge_base_ingestion_max_age_in_days``, default 7 days).
    - FAIL: The data source has no successfully completed ingestion job, or the latest one
      is older than the configured window, so the knowledge base may be serving stale data.
    - MANUAL: ListIngestionJobs failed for the data source, ListDataSources failed for the
      knowledge base, or ListKnowledgeBases failed for the region, so ingestion state is
      unknown.
    """

    def execute(self) -> list[Check_Report_AWS]:
        findings = []

        max_age_in_days = bedrock_agent_client.audit_config.get(
            "bedrock_knowledge_base_ingestion_max_age_in_days", 7
        )

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
            report.status_extended = f"Bedrock knowledge bases could not be listed in region {region} ({error}); verify manually that every knowledge base data source has recently completed an ingestion job."
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
            report.status_extended = f"Bedrock knowledge base {knowledge_base.name} data sources could not be listed in region {knowledge_base.region}{reason}; verify manually that each one has recently completed an ingestion job."
            findings.append(report)

        for data_source in bedrock_agent_client.data_sources.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=data_source)
            knowledge_base = (
                data_source.knowledge_base_name or data_source.knowledge_base_id
            )

            if not data_source.ingestion_jobs_listed:
                report.status = "MANUAL"
                reason = (
                    f" ({data_source.ingestion_jobs_error})"
                    if data_source.ingestion_jobs_error
                    else ""
                )
                report.status_extended = f"Bedrock knowledge base {knowledge_base} data source {data_source.name} ingestion jobs could not be listed in region {data_source.region}{reason}; verify manually that it has recently completed an ingestion job."
            elif data_source.last_successful_ingestion_at is None:
                report.status = "FAIL"
                report.status_extended = f"Bedrock knowledge base {knowledge_base} data source {data_source.name} has no successfully completed ingestion job in region {data_source.region}."
            else:
                age_in_days = (
                    datetime.now(timezone.utc)
                    - data_source.last_successful_ingestion_at
                ).days
                if age_in_days <= max_age_in_days:
                    report.status = "PASS"
                    report.status_extended = f"Bedrock knowledge base {knowledge_base} data source {data_source.name} completed an ingestion job {age_in_days} day(s) ago in region {data_source.region}, within the {max_age_in_days} day(s) threshold."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Bedrock knowledge base {knowledge_base} data source {data_source.name} last completed an ingestion job {age_in_days} day(s) ago in region {data_source.region}, exceeding the {max_age_in_days} day(s) threshold."
            findings.append(report)

        return findings
