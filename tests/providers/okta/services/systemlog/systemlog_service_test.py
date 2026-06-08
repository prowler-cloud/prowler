import json
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


class Test_SystemLog_service_sdk_validation_fallback:
    """Verifies the raw-JSON fallback when the Okta SDK rejects API values.

    The SDK's `LogStreamSettingsAws.eventSourceName` validator uses the
    regex `^[a-zA-Z0-9.\\-_]$` — missing the `+` quantifier, so every
    multi-character name raises pydantic `ValidationError`. Without the
    fallback the whole stream list is lost; with it, the raw JSON path
    still surfaces each stream's id/name/status/type.
    """

    def test_raw_fallback_projects_streams_when_sdk_raises(self):
        from pydantic import ValidationError

        provider = set_mocked_okta_provider()

        raw_payload = [
            {
                "id": "log-1",
                "name": "EventBridge prod",
                "status": "ACTIVE",
                "type": "AWS_EVENTBRIDGE",
            },
            {
                "id": "log-2",
                "name": "Splunk staging",
                "status": "INACTIVE",
                "type": "SPLUNK_CLOUD_LOGSTREAMING",
            },
        ]

        async def failing_list_log_streams(*_a, **_k):
            try:
                # Trigger a real pydantic ValidationError so we exercise
                # the exact exception type the SDK raises in production.
                from okta.models.log_stream_settings_aws import LogStreamSettingsAws

                LogStreamSettingsAws(
                    accountId="123456789012",
                    eventSourceName="MultiCharacter",
                    region="us-east-1",
                )
            except ValidationError as ve:
                raise ve
            return ([], _resp({}), None)

        async def fake_raw_create(*_a, **_k):
            return ({"url": "/api/v1/logStreams"}, None)

        async def fake_raw_execute(_request):
            return (None, json.dumps(raw_payload), None)

        sdk = mock.MagicMock()
        sdk.list_log_streams = failing_list_log_streams
        sdk._request_executor.create_request = fake_raw_create
        sdk._request_executor.execute = fake_raw_execute

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient",
            return_value=sdk,
        ):
            service = SystemLog(provider)

        assert set(service.log_streams.keys()) == {"log-1", "log-2"}
        assert service.log_streams["log-1"].status == "ACTIVE"
        assert service.log_streams["log-2"].status == "INACTIVE"
        assert service.log_streams["log-2"].type == "SPLUNK_CLOUD_LOGSTREAMING"

    def test_raw_fallback_handles_empty_list(self):
        from pydantic import ValidationError

        provider = set_mocked_okta_provider()

        async def failing(*_a, **_k):
            raise ValidationError.from_exception_data(
                title="LogStreamSettingsAws",
                line_errors=[],
            )

        async def fake_create(*_a, **_k):
            return ({"url": "/api/v1/logStreams"}, None)

        async def fake_execute(_req):
            return (None, "[]", None)

        sdk = mock.MagicMock()
        sdk.list_log_streams = failing
        sdk._request_executor.create_request = fake_create
        sdk._request_executor.execute = fake_execute

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient",
            return_value=sdk,
        ):
            service = SystemLog(provider)

        assert service.log_streams == {}
