from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled"


def _rule(name, state, recipient_domain_is=None):
    from prowler.providers.m365.services.defender.defender_service import (
        PresetSecurityPolicyRule,
    )

    return PresetSecurityPolicyRule(
        name=name,
        state=state,
        recipient_domain_is=(
            recipient_domain_is if recipient_domain_is is not None else ["contoso.com"]
        ),
    )


class Test_defender_strict_preset_security_policy_enabled:
    def _run(self, eop, atp):
        defender_client = mock.MagicMock()
        defender_client.audited_domain = DOMAIN
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.defender_client", new=defender_client),
        ):
            from prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled import (
                defender_strict_preset_security_policy_enabled,
            )

            defender_client.eop_protection_policy_rules = eop
            defender_client.atp_protection_policy_rules = atp
            return defender_strict_preset_security_policy_enabled().execute()

    def test_both_enabled(self):
        result = self._run(
            [_rule("Strict Preset Security Policy", "Enabled")],
            [_rule("Strict Preset Security Policy", "Enabled")],
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_only_eop(self):
        result = self._run(
            [_rule("Strict Preset Security Policy", "Enabled")],
            [],
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_disabled(self):
        result = self._run(
            [_rule("Strict Preset Security Policy", "Disabled")],
            [_rule("Strict Preset Security Policy", "Disabled")],
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_enabled_but_no_recipients(self):
        result = self._run(
            [_rule("Strict Preset Security Policy", "Enabled", recipient_domain_is=[])],
            [_rule("Strict Preset Security Policy", "Enabled", recipient_domain_is=[])],
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
