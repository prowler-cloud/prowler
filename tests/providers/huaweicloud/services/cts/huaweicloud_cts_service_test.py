from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.cts.cts_service import CTS, Tracker
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)

REGION = "la-south-2"


def _build_cts(service_client):
    """Build a CTS service whose fetch runs against the given mocked client.

    CTS is regional, so it fetches through the per-region clients returned by
    ``generate_regional_clients`` and dispatched with ``__threading_call__``.
    """
    provider = set_mocked_huaweicloud_provider(region=REGION)
    provider.generate_regional_clients = mock.MagicMock(
        return_value={REGION: service_client}
    )
    return CTS(provider)


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
