from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestConfigComplianceRules:
    def test_no_rules_fails(self):
        config_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.config.config_compliance_rules.config_compliance_rules.config_client",
                new=config_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.config.config_compliance_rules.config_compliance_rules import (
                config_compliance_rules,
            )

            config_client.policy_assignments = []
            config_client.audited_account = "123456789012"
            config_client.region = "la-south-2"

            check = config_compliance_rules()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "No compliance rules" in result[0].status_extended

    def test_enabled_rule_passes(self):
        config_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.config.config_compliance_rules.config_compliance_rules.config_client",
                new=config_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.config.config_service import (
                PolicyAssignment,
            )
            from prowler.providers.huaweicloud.services.config.config_compliance_rules.config_compliance_rules import (
                config_compliance_rules,
            )

            config_client.policy_assignments = [
                PolicyAssignment(
                    id="assignment-001",
                    name="check-encryption",
                    state="Enabled",
                    policy_definition_id="definition-001",
                ),
            ]
            config_client.audited_account = "123456789012"
            config_client.region = "la-south-2"

            check = config_compliance_rules()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "is enabled" in result[0].status_extended

    def test_disabled_rule_fails(self):
        config_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.config.config_compliance_rules.config_compliance_rules.config_client",
                new=config_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.config.config_service import (
                PolicyAssignment,
            )
            from prowler.providers.huaweicloud.services.config.config_compliance_rules.config_compliance_rules import (
                config_compliance_rules,
            )

            config_client.policy_assignments = [
                PolicyAssignment(
                    id="assignment-001",
                    name="check-encryption",
                    state="Disabled",
                    policy_definition_id="definition-001",
                ),
            ]
            config_client.audited_account = "123456789012"
            config_client.region = "la-south-2"

            check = config_compliance_rules()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not enabled" in result[0].status_extended

    def test_mixed_rules(self):
        config_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.config.config_compliance_rules.config_compliance_rules.config_client",
                new=config_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.config.config_service import (
                PolicyAssignment,
            )
            from prowler.providers.huaweicloud.services.config.config_compliance_rules.config_compliance_rules import (
                config_compliance_rules,
            )

            config_client.policy_assignments = [
                PolicyAssignment(
                    id="assignment-001",
                    name="check-encryption",
                    state="Enabled",
                    policy_definition_id="definition-001",
                ),
                PolicyAssignment(
                    id="assignment-002",
                    name="check-public-access",
                    state="Disabled",
                    policy_definition_id="definition-002",
                ),
            ]
            config_client.audited_account = "123456789012"
            config_client.region = "la-south-2"

            check = config_compliance_rules()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[1].status == "FAIL"
