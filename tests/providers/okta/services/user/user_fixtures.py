"""Shared helpers for `user` service check tests."""

from unittest import mock

from prowler.providers.okta.services.user.user_service import (
    ExternalDirectoryIdp,
    UserAutomation,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def build_user_client(
    automations: dict = None,
    external_directory_idps: dict = None,
    audit_config: dict = None,
    missing_scope: dict = None,
):
    client = mock.MagicMock()
    client.automations = automations or {}
    client.external_directory_idps = external_directory_idps or {}
    client.provider = set_mocked_okta_provider()
    client.audit_config = audit_config or {}
    client.missing_scope = missing_scope or {
        "automations": None,
        "identity_providers": None,
    }
    return client


def automation(
    automation_id: str = "auto-1",
    name: str = "User Inactivity",
    status: str = "ACTIVE",
    schedule_status: str = "ACTIVE",
    inactivity_days: int = 35,
    lifecycle_action: str = "SUSPENDED",
    groups: list = None,
):
    return UserAutomation(
        id=automation_id,
        name=name,
        status=status,
        schedule_status=schedule_status,
        inactivity_days=inactivity_days,
        lifecycle_action=lifecycle_action,
        applies_to_groups=groups or ["everyone"],
    )


def ad_idp(idp_id: str = "0oa-ad", name: str = "Corp AD"):
    return ExternalDirectoryIdp(
        id=idp_id, name=name, type="ACTIVE_DIRECTORY", status="ACTIVE"
    )
