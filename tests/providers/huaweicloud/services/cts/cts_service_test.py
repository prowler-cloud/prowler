from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.cts.cts_service import CTS, Tracker
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)

REGION = "la-south-2"


def _build_cts(service_client):
    """Build a CTS service whose fetch runs against the given mocked client.

    CTS is registered as a global service, so the base HuaweiCloudService never
    populates ``regional_clients`` (it only does so for regional services). The
    ``_list_trackers`` method, however, reads from ``self.regional_clients``, so
    we inject the client and re-run the fetch to exercise the parsing path.
    """
    provider = set_mocked_huaweicloud_provider(region=REGION)
    provider.session.client = mock.MagicMock(return_value=service_client)

    cts = CTS(provider)
    cts.regional_clients = {REGION: service_client}
    cts.trackers = []
    cts._list_trackers()
    return cts


class TestCTSService:
    def test_list_trackers_parses_trackers(self):
        trackers = [
            SimpleNamespace(
                id="tracker-1",
                tracker_name="system",
                tracker_type="system",
                status="enabled",
                obs_info=SimpleNamespace(
                    bucket_name="audit-bucket", file_prefix_name="cts/"
                ),
            ),
            SimpleNamespace(
                id="tracker-2",
                tracker_name="data-tracker",
                tracker_type="data",
                status="disabled",
                obs_info=None,
            ),
        ]
        service_client = mock.MagicMock(region=REGION)
        service_client.list_trackers.return_value = SimpleNamespace(trackers=trackers)

        cts = _build_cts(service_client)

        assert len(cts.trackers) == 2
        by_id = {tracker.id: tracker for tracker in cts.trackers}

        enabled = by_id["tracker-1"]
        assert isinstance(enabled, Tracker)
        assert enabled.name == "system"
        assert enabled.region == REGION
        assert enabled.is_enabled is True
        assert enabled.bucket_name == "audit-bucket"
        assert enabled.file_prefix_name == "cts/"

        disabled = by_id["tracker-2"]
        assert disabled.name == "data-tracker"
        assert disabled.is_enabled is False
        assert disabled.bucket_name == ""

    def test_list_trackers_empty(self):
        service_client = mock.MagicMock(region=REGION)
        service_client.list_trackers.return_value = SimpleNamespace(trackers=[])

        cts = _build_cts(service_client)

        assert cts.trackers == []

    def test_list_trackers_handles_sdk_error(self):
        service_client = mock.MagicMock(region=REGION)
        service_client.list_trackers.side_effect = Exception("boom")

        cts = _build_cts(service_client)

        # Errors are logged and swallowed; no partial/garbage resources.
        assert cts.trackers == []
