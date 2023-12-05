from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.wafv2.wafv2_service import WebAclv2
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)

waf_id = str(uuid4())
waf_name = "waf-example"
waf_arn = f"arn:aws:wafv2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:regional/webacl/{waf_name}/{waf_id}"


class Test_wafv2_webacl_logging_enabled:
    def test_no_web_acls(self):
        wafv2_client = mock.MagicMock
        wafv2_client.web_acls = []
        with mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.WAFv2",
            new=wafv2_client,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_client.wafv2_client",
            new=wafv2_client,
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
                arn=waf_arn,
                name=waf_name,
                id=waf_id,
                albs=[],
                region=AWS_REGION_EU_WEST_1,
                logging_enabled=True,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.WAFv2",
            new=wafv2_client,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_client.wafv2_client",
            new=wafv2_client,
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_logging_enabled.wafv2_webacl_logging_enabled import (
                wafv2_webacl_logging_enabled,
            )

            check = wafv2_webacl_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf_id} has logging enabled."
            )
            assert result[0].resource_id == waf_id
            assert result[0].resource_arn == waf_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_wafv2_wb_acl_without_logging(self):
        wafv2_client = mock.MagicMock
        wafv2_client.web_acls = []
        wafv2_client.enabled = True
        wafv2_client.web_acls.append(
            WebAclv2(
                arn=waf_arn,
                name=waf_name,
                id=waf_id,
                albs=[],
                region=AWS_REGION_EU_WEST_1,
                logging_enabled=False,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.WAFv2",
            new=wafv2_client,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_client.wafv2_client",
            new=wafv2_client,
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_logging_enabled.wafv2_webacl_logging_enabled import (
                wafv2_webacl_logging_enabled,
            )

            check = wafv2_webacl_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf_id} does not have logging enabled."
            )
            assert result[0].resource_id == waf_id
            assert result[0].resource_arn == waf_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
