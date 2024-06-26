from unittest import mock

from prowler.providers.aws.services.ssm.ssm_service import Document
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_ssm_documents_secrets:
    def test_no_documents(self):
        ssm_client = mock.MagicMock
        ssm_client.documents = {}
        with mock.patch(
            "prowler.providers.aws.services.ssm.ssm_service.SSM",
            new=ssm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssm.ssm_document_secrets.ssm_document_secrets import (
                ssm_document_secrets,
            )

            check = ssm_document_secrets()
            result = check.execute()

            assert len(result) == 0

    def test_document_with_secrets(self):
        ssm_client = mock.MagicMock
        document_name = "test-document"
        document_arn = f"arn:aws:ssm:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:document/{document_name}"
        ssm_client.audited_account = AWS_ACCOUNT_NUMBER
        ssm_client.documents = {
            document_name: Document(
                arn=document_arn,
                name=document_name,
                region=AWS_REGION_US_EAST_1,
                content={"db_password": "test-password"},
                account_owners=[],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.ssm.ssm_service.SSM",
            new=ssm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssm.ssm_document_secrets.ssm_document_secrets import (
                ssm_document_secrets,
            )

            check = ssm_document_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == document_name
            assert result[0].resource_arn == document_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in SSM Document {document_name} -> Secret Keyword on line 2."
            )

    def test_document_no_secrets(self):
        ssm_client = mock.MagicMock
        document_name = "test-document"
        document_arn = f"arn:aws:ssm:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:document/{document_name}"
        ssm_client.audited_account = AWS_ACCOUNT_NUMBER
        ssm_client.documents = {
            document_name: Document(
                arn=document_arn,
                name=document_name,
                region=AWS_REGION_US_EAST_1,
                content={"profile": "test"},
                account_owners=[],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.ssm.ssm_service.SSM",
            new=ssm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssm.ssm_document_secrets.ssm_document_secrets import (
                ssm_document_secrets,
            )

            check = ssm_document_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == document_name
            assert result[0].resource_arn == document_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in SSM Document {document_name}."
            )
