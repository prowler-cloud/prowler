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


class Test_defender_additional_email_configured_with_a_security_contact:
    def test_defender_no_subscriptions(self):
        defender_client = mock.MagicMock()
        defender_client.security_contact_configurations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact import (
                defender_additional_email_configured_with_a_security_contact,
            )

            check = defender_additional_email_configured_with_a_security_contact()
            result = check.execute()
            assert len(result) == 0

    def test_defender_no_additional_emails(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock()
        defender_client.security_contact_configurations = {
            AZURE_SUBSCRIPTION_ID: {
                resource_id: SecurityContactConfiguration(
                    id=resource_id,
                    name="default",
                    enabled=True,
                    emails=[],
                    phone="",
                    notifications_by_role=NotificationsByRole(
                        state=True, roles=["Contributor"]
                    ),
                    alert_minimal_severity=None,
                    attack_path_minimal_risk_level=None,
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact import (
                defender_additional_email_configured_with_a_security_contact,
            )

            check = defender_additional_email_configured_with_a_security_contact()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"There is not another correct email configured for subscription {AZURE_SUBSCRIPTION_ID}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "default"
            assert result[0].resource_id == resource_id

    def test_defender_additional_email_configured(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock()
        defender_client.security_contact_configurations = {
            AZURE_SUBSCRIPTION_ID: {
                resource_id: SecurityContactConfiguration(
                    id=resource_id,
                    name="default",
                    enabled=True,
                    emails=["test@test.com"],
                    phone="",
                    notifications_by_role=NotificationsByRole(
                        state=True, roles=["Contributor"]
                    ),
                    alert_minimal_severity=None,
                    attack_path_minimal_risk_level=None,
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact import (
                defender_additional_email_configured_with_a_security_contact,
            )

            check = defender_additional_email_configured_with_a_security_contact()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"There is another correct email configured for subscription {AZURE_SUBSCRIPTION_ID}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "default"
            assert result[0].resource_id == resource_id
