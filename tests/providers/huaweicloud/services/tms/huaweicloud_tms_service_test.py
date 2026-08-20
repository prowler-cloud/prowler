from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.tms.tms_service import TMS
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)

REGION = "eu-west-101"


def _provider_with_client(service_client):
    """Return a non-mock TMS provider whose client is the given mock."""
    provider = set_mocked_huaweicloud_provider(region=REGION)
    provider.session.is_mock = False
    provider.session.client = mock.MagicMock(return_value=service_client)
    return provider


class TestTMSService:
    def test_real_session_without_is_mock_loads_inventory(self):
        service_client = mock.MagicMock(region=REGION)
        service_client.list_predefine_tags.return_value = SimpleNamespace(
            tags=[], marker=None, total_count=0
        )
        provider = set_mocked_huaweicloud_provider(region=REGION)
        provider.session = SimpleNamespace(
            client=mock.MagicMock(return_value=service_client)
        )

        tms = TMS(provider)

        assert tms.predefined_tags == []

    def test_lists_every_predefined_tag_page(self):
        service_client = mock.MagicMock(region=REGION)
        service_client.list_predefine_tags.side_effect = [
            SimpleNamespace(
                tags=[
                    SimpleNamespace(key="environment", value="production"),
                    SimpleNamespace(key="owner", value="platform"),
                ],
                marker="2",
                total_count=3,
            ),
            SimpleNamespace(
                tags=[SimpleNamespace(key="project", value="prowler")],
                marker="3",
                total_count=3,
            ),
        ]

        tms = TMS(_provider_with_client(service_client))

        assert [(tag.key, tag.value) for tag in tms.predefined_tags] == [
            ("environment", "production"),
            ("owner", "platform"),
            ("project", "prowler"),
        ]
        requests = [
            call.args[0] for call in service_client.list_predefine_tags.call_args_list
        ]
        assert [request.marker for request in requests] == [None, "2"]
        assert all(request.limit == 1000 for request in requests)

    def test_marks_inventory_unknown_when_listing_fails(self):
        service_client = mock.MagicMock(region=REGION)
        service_client.list_predefine_tags.side_effect = Exception("denied")

        tms = TMS(_provider_with_client(service_client))

        assert tms.predefined_tags is None
