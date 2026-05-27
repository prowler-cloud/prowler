from unittest import mock

from prowler.providers.okta.models import OktaIdentityInfo
from prowler.providers.okta.services.systemlog.systemlog_service import (
    LogStream,
    SystemLog,
)
from tests.providers.okta.okta_fixtures import (
    OKTA_CLIENT_ID,
    OKTA_ORG_DOMAIN,
    set_mocked_okta_provider,
)


def _resp(headers: dict = None):
    r = mock.MagicMock()
    r.headers = headers or {}
    return r


def _fake_stream(
    stream_id: str, name: str, status: str = "ACTIVE", type_: str = "AWS_EVENTBRIDGE"
):
    s = mock.MagicMock()
    s.id = stream_id
    s.name = name
    s.status = status
    s.type = type_
    return s


def _patch_sdk(**methods):
    return mock.patch(
        "prowler.providers.okta.lib.service.service.OktaSDKClient",
        return_value=mock.MagicMock(**methods),
    )


class Test_SystemLog_service:
    def test_fetches_active_streams(self):
        provider = set_mocked_okta_provider()
        s1 = _fake_stream("log-1", "EventBridge")
        s2 = _fake_stream("log-2", "Splunk", type_="SPLUNK_CLOUD_LOGSTREAMING")

        async def fake_list(*_a, **_k):
            return ([s1, s2], _resp({}), None)

        with _patch_sdk(list_log_streams=fake_list):
            service = SystemLog(provider)

        assert set(service.log_streams.keys()) == {"log-1", "log-2"}
        assert isinstance(service.log_streams["log-1"], LogStream)
        assert service.log_streams["log-2"].type == "SPLUNK_CLOUD_LOGSTREAMING"

    def test_returns_empty_on_api_error(self):
        provider = set_mocked_okta_provider()

        async def failing(*_a, **_k):
            return ([], _resp({}), Exception("E0000007"))

        with _patch_sdk(list_log_streams=failing):
            service = SystemLog(provider)

        assert service.log_streams == {}

    def test_skips_fetch_when_scope_missing(self):
        identity = OktaIdentityInfo(
            org_domain=OKTA_ORG_DOMAIN,
            client_id=OKTA_CLIENT_ID,
            granted_scopes=["okta.policies.read"],  # no logStreams scope
        )
        provider = set_mocked_okta_provider(identity=identity)

        called = False

        async def fake_list(*_a, **_k):
            nonlocal called
            called = True
            return ([], _resp({}), None)

        with _patch_sdk(list_log_streams=fake_list):
            service = SystemLog(provider)

        assert called is False
        assert service.log_streams == {}
        assert service.missing_scope["log_streams"] == "okta.logStreams.read"
