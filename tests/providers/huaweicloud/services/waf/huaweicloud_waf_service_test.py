from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.waf.waf_service import WAF, WAFInstance
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)

REGION = "la-south-2"


def _provider_with_client(service_client):
    """Return a mocked provider whose regional client is the given mock."""
    provider = set_mocked_huaweicloud_provider(region=REGION)
    provider.session.client = mock.MagicMock(return_value=service_client)
    provider.generate_regional_clients = mock.MagicMock(
        return_value={REGION: service_client}
    )
    return provider


class TestWAFService:
    def test_list_instances_parses_instances(self):
        instances = [
            SimpleNamespace(id="waf-1", instancename="waf-primary", status=1),
            # Fallback to instance_name when instancename is missing/empty.
            SimpleNamespace(id="waf-2", instance_name="waf-fallback", status=0),
        ]
        service_client = mock.MagicMock(region=REGION)
        service_client.list_instance.return_value = SimpleNamespace(items=instances)

        waf = WAF(_provider_with_client(service_client))

        assert len(waf.instances) == 2
        by_id = {inst.id: inst for inst in waf.instances}

        primary = by_id["waf-1"]
        assert isinstance(primary, WAFInstance)
        assert primary.name == "waf-primary"
        assert primary.status == 1
        assert primary.region == REGION

        fallback = by_id["waf-2"]
        assert fallback.name == "waf-fallback"
        assert fallback.status == 0

    def test_list_instances_empty(self):
        service_client = mock.MagicMock(region=REGION)
        service_client.list_instance.return_value = SimpleNamespace(items=[])

        waf = WAF(_provider_with_client(service_client))

        assert waf.instances == []

    def test_list_instances_handles_sdk_error(self):
        service_client = mock.MagicMock(region=REGION)
        service_client.list_instance.side_effect = Exception("boom")

        waf = WAF(_provider_with_client(service_client))

        # Errors are logged and swallowed; no partial/garbage resources.
        assert waf.instances == []
