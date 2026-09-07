from types import SimpleNamespace
from unittest import mock

import pytest

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


def _defender_client():
    defender_client = mock.MagicMock()
    defender_client.audited_tenant = "audited_tenant"
    defender_client.audited_domain = DOMAIN
    defender_client.audit_config = {}
    return defender_client


def _run_check(module_path, class_name, defender_client):
    fake_client_module = SimpleNamespace(defender_client=defender_client)
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_m365_provider(),
        ),
        mock.patch(
            "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
        ),
        mock.patch.dict(
            "sys.modules",
            {
                "prowler.providers.m365.services.defender.defender_client": fake_client_module
            },
        ),
    ):
        module = __import__(module_path, fromlist=[class_name])
        return getattr(module, class_name)().execute()


def _malware_policy(identity, is_default):
    from prowler.providers.m365.services.defender.defender_service import MalwarePolicy

    return MalwarePolicy(
        identity=identity,
        enable_file_filter=True,
        enable_internal_sender_admin_notifications=True,
        internal_sender_admin_address="admin@example.com",
        file_types=["exe"],
        is_default=is_default,
    )


def _antiphishing_policy(name, default):
    from prowler.providers.m365.services.defender.defender_service import (
        AntiphishingPolicy,
    )

    return AntiphishingPolicy(
        name=name,
        spoof_intelligence=True,
        spoof_intelligence_action="Quarantine",
        dmarc_reject_action="Quarantine",
        dmarc_quarantine_action="Quarantine",
        safety_tips=True,
        unauthenticated_sender_action=True,
        show_tag=True,
        honor_dmarc_policy=True,
        default=default,
    )


def _outbound_spam_policy(name, default):
    from prowler.providers.m365.services.defender.defender_service import (
        OutboundSpamPolicy,
    )

    return OutboundSpamPolicy(
        name=name,
        notify_sender_blocked=True,
        notify_limit_exceeded=True,
        notify_limit_exceeded_addresses=["admin@example.com"],
        notify_sender_blocked_addresses=["admin@example.com"],
        auto_forwarding_mode="Off",
        default=default,
    )


@pytest.mark.parametrize(
    ("module_path", "class_name"),
    [
        (
            "prowler.providers.m365.services.defender.defender_malware_policy_notifications_internal_users_malware_enabled.defender_malware_policy_notifications_internal_users_malware_enabled",
            "defender_malware_policy_notifications_internal_users_malware_enabled",
        ),
        (
            "prowler.providers.m365.services.defender.defender_malware_policy_common_attachments_filter_enabled.defender_malware_policy_common_attachments_filter_enabled",
            "defender_malware_policy_common_attachments_filter_enabled",
        ),
        (
            "prowler.providers.m365.services.defender.defender_malware_policy_comprehensive_attachments_filter_applied.defender_malware_policy_comprehensive_attachments_filter_applied",
            "defender_malware_policy_comprehensive_attachments_filter_applied",
        ),
    ],
)
def test_malware_checks_skip_preset_policy_without_filter_rule(module_path, class_name):
    defender_client = _defender_client()
    defender_client.audit_config = {"recommended_blocked_file_types": ["exe"]}
    defender_client.malware_policies = [
        _malware_policy("Default", True),
        _malware_policy("Standard Preset Security Policy", False),
    ]
    defender_client.malware_rules = {"Other Policy": mock.MagicMock()}

    result = _run_check(module_path, class_name, defender_client)

    assert len(result) == 1
    assert result[0].resource_name == "Default"


def test_antiphishing_check_skips_preset_policy_without_rule():
    module_path = "prowler.providers.m365.services.defender.defender_antiphishing_policy_configured.defender_antiphishing_policy_configured"
    defender_client = _defender_client()
    defender_client.antiphishing_policies = {
        "Default": _antiphishing_policy("Default", True),
        "Standard Preset Security Policy": _antiphishing_policy(
            "Standard Preset Security Policy", False
        ),
    }
    defender_client.antiphishing_rules = {"Other Policy": mock.MagicMock()}

    result = _run_check(
        module_path, "defender_antiphishing_policy_configured", defender_client
    )

    assert len(result) == 1
    assert result[0].resource_name == "Default"


@pytest.mark.parametrize(
    ("module_path", "class_name"),
    [
        (
            "prowler.providers.m365.services.defender.defender_antispam_outbound_policy_configured.defender_antispam_outbound_policy_configured",
            "defender_antispam_outbound_policy_configured",
        ),
        (
            "prowler.providers.m365.services.defender.defender_antispam_outbound_policy_forwarding_disabled.defender_antispam_outbound_policy_forwarding_disabled",
            "defender_antispam_outbound_policy_forwarding_disabled",
        ),
    ],
)
def test_outbound_spam_checks_skip_preset_policy_without_rule(module_path, class_name):
    defender_client = _defender_client()
    defender_client.outbound_spam_policies = {
        "Default": _outbound_spam_policy("Default", True),
        "Standard Preset Security Policy": _outbound_spam_policy(
            "Standard Preset Security Policy", False
        ),
    }
    defender_client.outbound_spam_rules = {"Other Policy": mock.MagicMock()}

    result = _run_check(module_path, class_name, defender_client)

    assert len(result) == 1
    assert result[0].resource_name == "Default"


def test_inbound_spam_check_skips_preset_policy_without_rule():
    from prowler.providers.m365.services.defender.defender_service import (
        DefenderInboundSpamPolicy,
    )

    module_path = "prowler.providers.m365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains"
    defender_client = _defender_client()
    defender_client.inbound_spam_policies = [
        DefenderInboundSpamPolicy(
            identity="Default", allowed_sender_domains=[], default=True
        ),
        DefenderInboundSpamPolicy(
            identity="Standard Preset Security Policy",
            allowed_sender_domains=[],
            default=False,
        ),
    ]
    defender_client.inbound_spam_rules = {"Other Policy": mock.MagicMock()}

    result = _run_check(
        module_path,
        "defender_antispam_policy_inbound_no_allowed_domains",
        defender_client,
    )

    assert len(result) == 1
    assert result[0].resource_name == "Default"
