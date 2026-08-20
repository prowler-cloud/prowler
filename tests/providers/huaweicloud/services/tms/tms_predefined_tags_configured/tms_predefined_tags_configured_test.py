from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestTmsPredefinedTagsConfigured:
    def test_one_tag_uses_singular_message(self):
        tms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.tms.tms_predefined_tags_configured.tms_predefined_tags_configured.tms_client",
                new=tms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.tms.tms_predefined_tags_configured.tms_predefined_tags_configured import (
                tms_predefined_tags_configured,
            )
            from prowler.providers.huaweicloud.services.tms.tms_service import (
                PredefinedTag,
            )

            tms_client.predefined_tags = [
                PredefinedTag(key="environment", value="production")
            ]
            tms_client.region = "eu-west-101"
            tms_client.audited_account = "123456789012"

            result = tms_predefined_tags_configured().execute()

            assert result[0].status_extended == "1 predefined tag is configured."

    def test_tags_configured_passes(self):
        tms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.tms.tms_predefined_tags_configured.tms_predefined_tags_configured.tms_client",
                new=tms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.tms.tms_predefined_tags_configured.tms_predefined_tags_configured import (
                tms_predefined_tags_configured,
            )
            from prowler.providers.huaweicloud.services.tms.tms_service import (
                PredefinedTag,
            )

            tms_client.predefined_tags = [
                PredefinedTag(key="environment", value="production"),
                PredefinedTag(key="owner", value="platform-team"),
            ]
            tms_client.region = "la-south-2"
            tms_client.audited_account = "123456789012"

            check = tms_predefined_tags_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "2 predefined tags are configured."
            assert result[0].resource_id == "123456789012-predefined-tags"
            assert result[0].resource_name == "TMS Predefined Tags"
            assert result[0].region == "la-south-2"
            assert result[0].resource_tags == []
            assert (
                result[0].resource_arn
                == "huaweicloud:tms:la-south-2:123456789012:predefined-tags"
            )

    def test_no_tags_fails(self):
        tms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.tms.tms_predefined_tags_configured.tms_predefined_tags_configured.tms_client",
                new=tms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.tms.tms_predefined_tags_configured.tms_predefined_tags_configured import (
                tms_predefined_tags_configured,
            )

            tms_client.predefined_tags = []
            tms_client.region = "la-south-2"
            tms_client.audited_account = "123456789012"

            check = tms_predefined_tags_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "No predefined tags are configured."
            assert result[0].resource_id == "123456789012-predefined-tags"

    def test_listing_failure_returns_no_findings(self):
        tms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.tms.tms_predefined_tags_configured.tms_predefined_tags_configured.tms_client",
                new=tms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.tms.tms_predefined_tags_configured.tms_predefined_tags_configured import (
                tms_predefined_tags_configured,
            )

            tms_client.predefined_tags = None

            result = tms_predefined_tags_configured().execute()

            assert result == []
