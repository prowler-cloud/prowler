from re import search
from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.wafv2.wafv2_service import WebAclv2

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"



class Test_wafv2_webacl_logging_enabled:
    def test_no_web_acls(self):
        wafv2_client = mock.MagicMock
        wafv2_client.web_acls = []
        with mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.WAFv2",
            wafv2_client,
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_logging_enabled.wafv2_webacl_logging_enabled import (
                wafv2_webacl_logging_enabled,
            )

            check = wafv2_webacl_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_wafv2_wb_acl_with_logging(self):
        wafv2_client = mock.MagicMock
        wafv2_client.web_acls = []
        wafv2_client.enabled = True
        wafv2_client.web_acls.append(
            WebAclv2(
                arn="arn",
                name="name",
                id="id",
                albs=[],
                region=AWS_REGION,
                logging_enabled=True,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.WAFv2",
            wafv2_client,
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_logging_enabled.wafv2_webacl_logging_enabled import (
                wafv2_webacl_logging_enabled,
            )

            check = wafv2_webacl_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search("has logging enabled", result[0].status_extended)
            assert result[0].resource_id == "id"

    def test_wafv2_wb_acl_without_logging(self):
        wafv2_client = mock.MagicMock
        wafv2_client.web_acls = []
        wafv2_client.enabled = True
        wafv2_client.web_acls.append(
            WebAclv2(
                arn="arn",
                name="name",
                id="id",
                albs=[],
                region=AWS_REGION,
                logging_enabled=False,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.WAFv2",
            wafv2_client,
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_logging_enabled.wafv2_webacl_logging_enabled import (
                wafv2_webacl_logging_enabled,
            )

            check = wafv2_webacl_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search("does not have logging enabled", result[0].status_extended)
            assert result[0].resource_id == "id"
