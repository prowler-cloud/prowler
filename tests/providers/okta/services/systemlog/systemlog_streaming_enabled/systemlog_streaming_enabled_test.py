from unittest import mock

from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.systemlog.systemlog_fixtures import (
    build_systemlog_client,
    log_stream,
)

CHECK_PATH = (
    "prowler.providers.okta.services.systemlog."
    "systemlog_streaming_enabled.systemlog_streaming_enabled.systemlog_client"
)


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=client),
    ):
        from prowler.providers.okta.services.systemlog.systemlog_streaming_enabled.systemlog_streaming_enabled import (
            systemlog_streaming_enabled,
        )

        return systemlog_streaming_enabled().execute()


class Test_systemlog_streaming_enabled:
    def test_pass_when_active_stream_exists(self):
        client = build_systemlog_client(
            log_streams={"log-1": log_stream(name="EventBridge prod")}
        )
        findings = _run_check(client)
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "EventBridge prod" in findings[0].status_extended

    def test_pass_when_multiple_active_streams(self):
        client = build_systemlog_client(
            log_streams={
                "log-1": log_stream(stream_id="log-1", name="A"),
                "log-2": log_stream(stream_id="log-2", name="B"),
            }
        )
        findings = _run_check(client)
        assert len(findings) == 2
        assert all(f.status == "PASS" for f in findings)

    def test_fail_when_all_streams_inactive(self):
        client = build_systemlog_client(
            log_streams={"log-1": log_stream(name="A", status="INACTIVE")}
        )
        findings = _run_check(client)
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "none are ACTIVE" in findings[0].status_extended

    def test_fail_when_no_streams_configured(self):
        client = build_systemlog_client(log_streams={})
        findings = _run_check(client)
        assert findings[0].status == "FAIL"
        assert "No Okta Log Streams are configured" in findings[0].status_extended
        assert "mutelist" in findings[0].status_extended

    def test_manual_when_scope_missing(self):
        client = build_systemlog_client(
            missing_scope={"log_streams": "okta.logStreams.read"}
        )
        findings = _run_check(client)
        assert findings[0].status == "MANUAL"
        assert "okta.logStreams.read" in findings[0].status_extended
