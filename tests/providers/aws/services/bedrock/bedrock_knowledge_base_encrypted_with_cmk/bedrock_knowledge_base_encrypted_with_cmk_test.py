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
KMS_KEY_ARN = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/test-key-id"

# Operations the BedrockAgent constructor calls that these tests do not exercise.
_UNUSED_OPERATIONS = (
    "ListAgents",
    "GetAgent",
    "ListPrompts",
    "GetPrompt",
    "ListTagsForResource",
)


def _knowledge_base_mock(kms_key_arn=None, fail_get=False):
    """Build a _make_api_call replacement returning one KB with one data source."""

    def _mock(self, operation_name, kwarg):
        if operation_name in _UNUSED_OPERATIONS:
            return {}
        if operation_name == "ListKnowledgeBases":
            return {
                "knowledgeBaseSummaries": [
                    {
                        "knowledgeBaseId": KB_ID,
                        "name": KB_NAME,
                        "status": "ACTIVE",
                    }
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
            if fail_get:
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    operation_name,
                )
            # GetDataSource nests its payload under a top-level dataSource key.
            data_source = {
                "knowledgeBaseId": KB_ID,
                "dataSourceId": DS_ID,
                "name": DS_NAME,
                "status": "AVAILABLE",
            }
            if kms_key_arn is not None:
                data_source["serverSideEncryptionConfiguration"] = {
                    "kmsKeyArn": kms_key_arn
                }
            return {"dataSource": data_source}
        return make_api_call(self, operation_name, kwarg)

    return _mock


_mock_with_cmk = _knowledge_base_mock(KMS_KEY_ARN)
_mock_without_cmk = _knowledge_base_mock(None)
_mock_empty_cmk = _knowledge_base_mock("")
_mock_unreadable = _knowledge_base_mock(fail_get=True)


def _mock_empty(self, operation_name, kwarg):
    """No knowledge bases at all."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListKnowledgeBases":
        return {"knowledgeBaseSummaries": []}
    return make_api_call(self, operation_name, kwarg)


def _mock_no_data_sources(self, operation_name, kwarg):
    """A knowledge base with no data sources produces no findings."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListKnowledgeBases":
        return {
            "knowledgeBaseSummaries": [
                {"knowledgeBaseId": KB_ID, "name": KB_NAME, "status": "ACTIVE"}
            ]
        }
    if operation_name == "ListDataSources":
        return {"dataSourceSummaries": []}
    return make_api_call(self, operation_name, kwarg)


def _mock_unsupported_region(self, operation_name, kwarg):
    """The API is not available in the audited region."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListKnowledgeBases":
        raise ClientError(
            {
                "Error": {
                    "Code": "ValidationException",
                    "Message": "Bedrock Agent is not supported in this region.",
                }
            },
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def _mock_list_kb_denied(self, operation_name, kwarg):
    """ListKnowledgeBases is denied, so the region's knowledge bases are unknown."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListKnowledgeBases":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def _mock_list_ds_denied(self, operation_name, kwarg):
    """The knowledge base is visible but its data sources cannot be listed."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListKnowledgeBases":
        return {
            "knowledgeBaseSummaries": [
                {"knowledgeBaseId": KB_ID, "name": KB_NAME, "status": "ACTIVE"}
            ]
        }
    if operation_name == "ListDataSources":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


class Test_bedrock_knowledge_base_encrypted_with_cmk:
    """Unit tests for the bedrock_knowledge_base_encrypted_with_cmk check."""

    def _run(self):
        """Import the service + check under the active mocks and execute."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_knowledge_base_encrypted_with_cmk.bedrock_knowledge_base_encrypted_with_cmk.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_knowledge_base_encrypted_with_cmk.bedrock_knowledge_base_encrypted_with_cmk import (
                bedrock_knowledge_base_encrypted_with_cmk,
            )

            return bedrock_knowledge_base_encrypted_with_cmk().execute()

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty)
    @mock_aws
    def test_no_resources(self):
        """No resources means no findings, not a spurious FAIL."""
        assert self._run() == []

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_no_data_sources)
    @mock_aws
    def test_knowledge_base_without_data_sources(self):
        """Findings are per data source, so a KB with none produces nothing."""
        assert self._run() == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_unsupported_region
    )
    @mock_aws
    def test_region_not_supported(self):
        """A ValidationException from the region must not raise; it yields no findings."""
        assert self._run() == []

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_cmk)
    @mock_aws
    def test_cmk_present_passes(self):
        """A data source with kmsKeyArn set is compliant."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == DS_ID
        assert result[0].resource_arn == DS_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].status_extended
            == f"Bedrock knowledge base {KB_NAME} data source {DS_NAME} is encrypted with a customer-managed KMS key in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_without_cmk)
    @mock_aws
    def test_no_cmk_fails(self):
        """An absent kmsKeyArn means an AWS-owned key is in use."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert KB_NAME in result[0].status_extended
        assert "is not encrypted with a customer-managed KMS key" in (
            result[0].status_extended
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty_cmk)
    @mock_aws
    def test_empty_cmk_fails(self):
        """An empty kmsKeyArn string is not a key."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "is not encrypted with a customer-managed KMS key" in (
            result[0].status_extended
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_unreadable)
    @mock_aws
    def test_detail_unreadable_is_manual_not_pass(self):
        """A failed GetDataSource must not be reported as compliant."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_list_kb_denied)
    @mock_aws
    def test_list_knowledge_bases_denied_is_manual_not_silence(self):
        """A denied ListKnowledgeBases must report MANUAL for the region."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "knowledge-base/unknown"
        assert (
            result[0].resource_arn
            == f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:knowledge-base/unknown"
        )
        assert "could not be listed" in result[0].status_extended
        assert "AccessDeniedException" in result[0].status_extended
        assert result[0].status_extended.endswith(".")

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_list_ds_denied)
    @mock_aws
    def test_list_data_sources_denied_is_manual_not_silence(self):
        """A knowledge base whose data sources cannot be listed must still report.

        Reporting nothing would drop the knowledge base from the output, which is
        indistinguishable from one that genuinely has no data sources.
        """
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_arn == KB_ARN
        assert KB_NAME in result[0].status_extended
        assert "data sources could not be listed" in result[0].status_extended
        # The message names why, like the region-level and detail-level ones do.
        assert "AccessDeniedException" in result[0].status_extended
        assert result[0].status_extended.endswith(".")

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_no_data_sources)
    @mock_aws
    def test_listed_but_empty_marks_the_knowledge_base_as_listed(self):
        """A successful but empty ListDataSources is "none", not "unknown".

        Distinct from test_knowledge_base_without_data_sources, which only asserts
        the empty result: this asserts the service state that produces it, so the
        over-correction of reporting MANUAL for a genuinely empty knowledge base
        cannot regress silently.
        """
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            service = BedrockAgent(aws_provider)

        assert service.knowledge_bases, "the knowledge base must be discovered"
        assert all(
            knowledge_base.data_sources_listed
            for knowledge_base in service.knowledge_bases.values()
        )
        assert service.data_sources == {}
        assert service.knowledge_bases_scan_errors == {}
        assert self._run() == []

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_without_cmk)
    @mock_aws
    def test_scoping_by_knowledge_base_arn_keeps_its_data_sources(self):
        """A scan scoped to the knowledge base ARN must still see its data sources.

        AWS exposes no ARN for a Bedrock data source, so the one built here is
        synthetic and can never equal a user-supplied --resource-arn. Filtering on
        it would keep the knowledge base, silently drop every data source, and
        leave the check reporting nothing for an in-scope knowledge base.
        """
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        aws_provider._audit_resources = [KB_ARN]
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            service = BedrockAgent(aws_provider)

        assert service.knowledge_bases, "the scoped knowledge base must be kept"
        assert service.data_sources, "its data sources must not be filtered out"
        assert all(
            ds.knowledge_base_id == KB_ID for ds in service.data_sources.values()
        )
