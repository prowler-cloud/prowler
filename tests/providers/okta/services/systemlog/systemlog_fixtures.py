"""Shared helpers for `systemlog` service check tests."""

from unittest import mock

from prowler.providers.okta.services.systemlog.systemlog_service import LogStream
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def build_systemlog_client(
    log_streams: dict = None,
    missing_scope: dict = None,
):
    client = mock.MagicMock()
    client.log_streams = log_streams or {}
    client.provider = set_mocked_okta_provider()
    client.audit_config = {}
    client.missing_scope = missing_scope or {"log_streams": None}
    return client


def log_stream(
    stream_id: str = "log-1",
    name: str = "EventBridge stream",
    status: str = "ACTIVE",
    type: str = "AWS_EVENTBRIDGE",
):
    return LogStream(id=stream_id, name=name, status=status, type=type)
