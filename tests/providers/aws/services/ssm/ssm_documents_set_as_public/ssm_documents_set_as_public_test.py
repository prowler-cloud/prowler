from unittest import mock

from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.services.ssm.ssm_service import Document
from tests.providers.aws.audit_info_utils import AWS_REGION_EU_WEST_1


class Test_ssm_documents_set_as_public:
    def test_no_documents(self):
        ssm_client = mock.MagicMock
        ssm_client.documents = {}
        with mock.patch(
            "prowler.providers.aws.services.ssm.ssm_service.SSM",
            new=ssm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssm.ssm_documents_set_as_public.ssm_documents_set_as_public import (
                ssm_documents_set_as_public,
            )

            check = ssm_documents_set_as_public()
            result = check.execute()

            assert len(result) == 0

    def test_document_public(self):
        ssm_client = mock.MagicMock
        document_name = "test-document"
        document_arn = f"arn:aws:ssm:{AWS_REGION_EU_WEST_1}:{DEFAULT_ACCOUNT_ID}:document/{document_name}"
        ssm_client.audited_account = DEFAULT_ACCOUNT_ID
        ssm_client.documents = {
            document_name: Document(
                arn=document_arn,
                name=document_name,
                region=AWS_REGION_EU_WEST_1,
                content="",
                account_owners=["111111111111", "111111222222"],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.ssm.ssm_service.SSM",
            new=ssm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssm.ssm_documents_set_as_public.ssm_documents_set_as_public import (
                ssm_documents_set_as_public,
            )

            check = ssm_documents_set_as_public()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == document_name
            assert result[0].resource_arn == document_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended == f"SSM Document {document_name} is public."
            )

    def test_document_not_public(self):
        ssm_client = mock.MagicMock
        document_name = "test-document"
        document_arn = f"arn:aws:ssm:{AWS_REGION_EU_WEST_1}:{DEFAULT_ACCOUNT_ID}:document/{document_name}"
        ssm_client.audited_account = DEFAULT_ACCOUNT_ID
        ssm_client.documents = {
            document_name: Document(
                arn=document_arn,
                name=document_name,
                region=AWS_REGION_EU_WEST_1,
                content="",
                account_owners=[],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.ssm.ssm_service.SSM",
            new=ssm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssm.ssm_documents_set_as_public.ssm_documents_set_as_public import (
                ssm_documents_set_as_public,
            )

            check = ssm_documents_set_as_public()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == document_name
            assert result[0].resource_arn == document_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SSM Document {document_name} is not public."
            )
