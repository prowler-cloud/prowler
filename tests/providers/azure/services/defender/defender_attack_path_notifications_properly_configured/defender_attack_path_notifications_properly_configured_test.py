from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import (
    NotificationsByRole,
    SecurityContactConfiguration,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_defender_attack_path_notifications_properly_configured:
    def test_no_subscriptions(self):
        defender_client = mock.MagicMock()
        defender_client.security_contact_configurations = {}
        defender_client.audit_config = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured import (
                defender_attack_path_notifications_properly_configured,
            )

            check = defender_attack_path_notifications_properly_configured()
            result = check.execute()
            assert len(result) == 0

    def test_attack_path_notifications_none(self):
        resource_id = str(uuid4())
        contact_name = "default"
        defender_client = mock.MagicMock()
        defender_client.security_contact_configurations = {
            AZURE_SUBSCRIPTION_ID: {
                resource_id: SecurityContactConfiguration(
                    id=resource_id,
                    name=contact_name,
                    enabled=True,
                    emails=[""],
                    phone="",
                    notifications_by_role=NotificationsByRole(
                        state=True, roles=["Owner"]
                    ),
                    alert_minimal_severity="High",
                    attack_path_minimal_risk_level=None,
                )
            }
        }
        defender_client.audit_config = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured import (
                defender_attack_path_notifications_properly_configured,
            )

            check = defender_attack_path_notifications_properly_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Attack path notifications are not enabled in subscription {AZURE_SUBSCRIPTION_ID} for security contact {contact_name}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == contact_name
            assert result[0].resource_id == resource_id

    def test_attack_path_notifications_custom_config(self):
        # Configured minimal risk level is Medium
        resource_id = str(uuid4())
        contact_name = "default"
        defender_client = mock.MagicMock()
        defender_client.security_contact_configurations = {
            AZURE_SUBSCRIPTION_ID: {
                resource_id: SecurityContactConfiguration(
                    id=resource_id,
                    name=contact_name,
                    enabled=True,
                    emails=[""],
                    phone="",
                    notifications_by_role=NotificationsByRole(
                        state=True, roles=["Owner"]
                    ),
                    alert_minimal_severity="High",
                    attack_path_minimal_risk_level="Medium",
                )
            }
        }
        defender_client.audit_config = {
            "defender_attack_path_minimal_risk_level": "Medium"
        }
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured import (
                defender_attack_path_notifications_properly_configured,
            )

            check = defender_attack_path_notifications_properly_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Attack path notifications are enabled with minimal risk level Medium in subscription {AZURE_SUBSCRIPTION_ID} for security contact {contact_name}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == contact_name
            assert result[0].resource_id == resource_id

    def test_attack_path_notifications_invalid_config(self):
        # Configured minimal risk level is invalid, should default to High
        resource_id = str(uuid4())
        contact_name = "default"
        defender_client = mock.MagicMock()
        defender_client.security_contact_configurations = {
            AZURE_SUBSCRIPTION_ID: {
                resource_id: SecurityContactConfiguration(
                    id=resource_id,
                    name=contact_name,
                    enabled=True,
                    emails=[""],
                    phone="",
                    notifications_by_role=NotificationsByRole(
                        state=True, roles=["Owner"]
                    ),
                    alert_minimal_severity="High",
                    attack_path_minimal_risk_level="Medium",
                )
            }
        }
        defender_client.audit_config = {
            "defender_attack_path_minimal_risk_level": "INVALID"
        }
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured import (
                defender_attack_path_notifications_properly_configured,
            )

            check = defender_attack_path_notifications_properly_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Attack path notifications are enabled with minimal risk level Medium in subscription {AZURE_SUBSCRIPTION_ID} for security contact {contact_name}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == contact_name
            assert result[0].resource_id == resource_id

    def test_attack_path_notifications_low_default_high(self):
        # Low risk level, default config (High) -> PASS
        resource_id = str(uuid4())
        contact_name = "default"
        defender_client = mock.MagicMock()
        defender_client.security_contact_configurations = {
            AZURE_SUBSCRIPTION_ID: {
                resource_id: SecurityContactConfiguration(
                    id=resource_id,
                    name=contact_name,
                    enabled=True,
                    emails=[""],
                    phone="",
                    notifications_by_role=NotificationsByRole(
                        state=True, roles=["Owner"]
                    ),
                    alert_minimal_severity="High",
                    attack_path_minimal_risk_level="Low",
                )
            }
        }
        defender_client.audit_config = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured import (
                defender_attack_path_notifications_properly_configured,
            )

            check = defender_attack_path_notifications_properly_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Attack path notifications are enabled with minimal risk level Low in subscription {AZURE_SUBSCRIPTION_ID} for security contact {contact_name}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == contact_name
            assert result[0].resource_id == resource_id

    def test_attack_path_notifications_medium_default_high(self):
        # Medium risk level, default config (High) -> PASS
        resource_id = str(uuid4())
        contact_name = "default"
        defender_client = mock.MagicMock()
        defender_client.security_contact_configurations = {
            AZURE_SUBSCRIPTION_ID: {
                resource_id: SecurityContactConfiguration(
                    id=resource_id,
                    name=contact_name,
                    enabled=True,
                    emails=[""],
                    phone="",
                    notifications_by_role=NotificationsByRole(
                        state=True, roles=["Owner"]
                    ),
                    alert_minimal_severity="High",
                    attack_path_minimal_risk_level="Medium",
                )
            }
        }
        defender_client.audit_config = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured import (
                defender_attack_path_notifications_properly_configured,
            )

            check = defender_attack_path_notifications_properly_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Attack path notifications are enabled with minimal risk level Medium in subscription {AZURE_SUBSCRIPTION_ID} for security contact {contact_name}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == contact_name
            assert result[0].resource_id == resource_id

    def test_attack_path_notifications_high_default_high(self):
        # High risk level, default config (High) -> PASS
        resource_id = str(uuid4())
        contact_name = "default"
        defender_client = mock.MagicMock()
        defender_client.security_contact_configurations = {
            AZURE_SUBSCRIPTION_ID: {
                resource_id: SecurityContactConfiguration(
                    id=resource_id,
                    name=contact_name,
                    enabled=True,
                    emails=[""],
                    phone="",
                    notifications_by_role=NotificationsByRole(
                        state=True, roles=["Owner"]
                    ),
                    alert_minimal_severity="High",
                    attack_path_minimal_risk_level="High",
                )
            }
        }
        defender_client.audit_config = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured import (
                defender_attack_path_notifications_properly_configured,
            )

            check = defender_attack_path_notifications_properly_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Attack path notifications are enabled with minimal risk level High in subscription {AZURE_SUBSCRIPTION_ID} for security contact {contact_name}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == contact_name
            assert result[0].resource_id == resource_id

    def test_attack_path_notifications_critical_default_high(self):
        # Critical risk level, default config (High) -> FAIL
        resource_id = str(uuid4())
        contact_name = "default"
        defender_client = mock.MagicMock()
        defender_client.security_contact_configurations = {
            AZURE_SUBSCRIPTION_ID: {
                resource_id: SecurityContactConfiguration(
                    id=resource_id,
                    name=contact_name,
                    enabled=True,
                    emails=[""],
                    phone="",
                    notifications_by_role=NotificationsByRole(
                        state=True, roles=["Owner"]
                    ),
                    alert_minimal_severity="High",
                    attack_path_minimal_risk_level="Critical",
                )
            }
        }
        defender_client.audit_config = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.defender.defender_attack_path_notifications_properly_configured.defender_attack_path_notifications_properly_configured import (
                defender_attack_path_notifications_properly_configured,
            )

            check = defender_attack_path_notifications_properly_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Attack path notifications are enabled with minimal risk level Critical in subscription {AZURE_SUBSCRIPTION_ID} for security contact {contact_name}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == contact_name
            assert result[0].resource_id == resource_id
