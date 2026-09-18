from datetime import datetime, timedelta, timezone
from unittest import mock

import botocore
from botocore.exceptions import ClientError
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

KB_ID = "test-kb-id"
KB_NAME = "test-knowledge-base"
KB_ARN = f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:knowledge-base/{KB_ID}"
DS_ID = "test-ds-id"
DS_NAME = "test-data-source"
DS_ARN = f"{KB_ARN}/data-source/{DS_ID}"

CHECK_PATH = "prowler.providers.aws.services.bedrock.bedrock_knowledge_base_ingestion_recently_completed.bedrock_knowledge_base_ingestion_recently_completed.bedrock_agent_client"

# Operations the BedrockAgent constructor calls that these tests do not exercise.
_UNUSED_OPERATIONS = (
    "ListAgents",
    "GetAgent",
    "ListPrompts",
    "GetPrompt",
    "ListTagsForResource",
)


def _base(operation_name):
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListKnowledgeBases":
        return {
            "knowledgeBaseSummaries": [
                {"knowledgeBaseId": KB_ID, "name": KB_NAME, "status": "ACTIVE"}
            ]
        }
    if operation_name == "ListDataSources":
        return {
            "dataSourceSummaries": [
                {
                    "knowledgeBaseId": KB_ID,
                    "dataSourceId": DS_ID,
                    "name": DS_NAME,
                    "status": "AVAILABLE",
                }
            ]
        }
    if operation_name == "GetDataSource":
        return {
            "dataSource": {
                "knowledgeBaseId": KB_ID,
                "dataSourceId": DS_ID,
                "name": DS_NAME,
                "status": "AVAILABLE",
            }
        }
    return None


def _make_mock(ingestion_summaries=None, fail_ingestion=False):
    def _mock(self, operation_name, kwarg):
        base = _base(operation_name)
        if base is not None:
            return base
        if operation_name == "ListIngestionJobs":
            if fail_ingestion:
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    operation_name,
                )
            return {"ingestionJobSummaries": ingestion_summaries or []}
        return make_api_call(self, operation_name, kwarg)

    return _mock


def _mock_empty(self, operation_name, kwarg):
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListKnowledgeBases":
        return {"knowledgeBaseSummaries": []}
    return make_api_call(self, operation_name, kwarg)


def _mock_list_kb_denied(self, operation_name, kwarg):
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListKnowledgeBases":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


class Test_bedrock_knowledge_base_ingestion_recently_completed:
    def _run(self):
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=BedrockAgent(aws_provider)),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_knowledge_base_ingestion_recently_completed.bedrock_knowledge_base_ingestion_recently_completed import (
                bedrock_knowledge_base_ingestion_recently_completed,
            )

            return bedrock_knowledge_base_ingestion_recently_completed().execute()

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty)
    @mock_aws
    def test_no_resources(self):
        assert self._run() == []

    @mock_aws
    def test_recent_ingestion_passes(self):
        recent = datetime.now(timezone.utc) - timedelta(days=2)
        summaries = [
            {"ingestionJobId": "job1", "status": "COMPLETE", "updatedAt": recent}
        ]
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_make_mock(ingestion_summaries=summaries),
        ):
            result = self._run()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == DS_ID
        assert result[0].resource_arn == DS_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert "within the 7 day(s) threshold" in result[0].status_extended

    @mock_aws
    def test_stale_ingestion_fails(self):
        stale = datetime.now(timezone.utc) - timedelta(days=30)
        summaries = [
            {"ingestionJobId": "job1", "status": "COMPLETE", "updatedAt": stale}
        ]
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_make_mock(ingestion_summaries=summaries),
        ):
            result = self._run()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "exceeding the 7 day(s) threshold" in result[0].status_extended

    @mock_aws
    def test_latest_complete_job_is_used(self):
        # A recent FAILED job and an older COMPLETE job: the latest *successful* one drives
        # the verdict, so this is stale -> FAIL.
        recent_failed = datetime.now(timezone.utc) - timedelta(days=1)
        old_complete = datetime.now(timezone.utc) - timedelta(days=20)
        summaries = [
            {"ingestionJobId": "job2", "status": "FAILED", "updatedAt": recent_failed},
            {"ingestionJobId": "job1", "status": "COMPLETE", "updatedAt": old_complete},
        ]
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_make_mock(ingestion_summaries=summaries),
        ):
            result = self._run()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_no_successful_ingestion_fails(self):
        recent_failed = datetime.now(timezone.utc) - timedelta(days=1)
        summaries = [
            {"ingestionJobId": "job1", "status": "FAILED", "updatedAt": recent_failed}
        ]
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_make_mock(ingestion_summaries=summaries),
        ):
            result = self._run()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "no successfully completed ingestion job" in result[0].status_extended

    @mock_aws
    def test_configurable_threshold(self):
        # 10-day-old job is stale with the default 7 but passes with a configured 30.
        job_time = datetime.now(timezone.utc) - timedelta(days=10)
        summaries = [
            {"ingestionJobId": "job1", "status": "COMPLETE", "updatedAt": job_time}
        ]
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1],
            audit_config={"bedrock_knowledge_base_ingestion_max_age_in_days": 30},
        )
        with (
            mock.patch(
                "botocore.client.BaseClient._make_api_call",
                new=_make_mock(ingestion_summaries=summaries),
            ),
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(CHECK_PATH, new=BedrockAgent(aws_provider)),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_knowledge_base_ingestion_recently_completed.bedrock_knowledge_base_ingestion_recently_completed import (
                bedrock_knowledge_base_ingestion_recently_completed,
            )

            result = bedrock_knowledge_base_ingestion_recently_completed().execute()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "within the 30 day(s) threshold" in result[0].status_extended

    @mock_aws
    def test_ingestion_jobs_listing_failed_is_manual(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_make_mock(fail_ingestion=True),
        ):
            result = self._run()

        assert len(result) == 1
        assert result[0].status == "MANUAL"

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_list_kb_denied)
    @mock_aws
    def test_list_knowledge_bases_denied_is_manual(self):
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "knowledge-base/unknown"
