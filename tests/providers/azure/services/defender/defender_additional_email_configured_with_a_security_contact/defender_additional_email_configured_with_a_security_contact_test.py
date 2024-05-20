from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import SecurityContacts
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_defender_additional_email_configured_with_a_security_contact:
    def test_defender_no_subscriptions(self):
        defender_client = mock.MagicMock
        defender_client.security_contacts = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact import (
                defender_additional_email_configured_with_a_security_contact,
            )

            check = defender_additional_email_configured_with_a_security_contact()
            result = check.execute()
            assert len(result) == 0

    def test_defender_no_additional_emails(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.security_contacts = {
            AZURE_SUBSCRIPTION_ID: {
                "default": SecurityContacts(
                    resource_id=resource_id,
                    emails="",
                    phone="",
                    alert_notifications_minimal_severity="High",
                    alert_notifications_state="On",
                    notified_roles=["Contributor"],
                    notified_roles_state="On",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact.defender_client",
            new=defender_client,
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
                == f"There is not another correct email configured for susbscription {AZURE_SUBSCRIPTION_ID}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "default"
            assert result[0].resource_id == resource_id

    def test_defender_additional_email_bad_format(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.security_contacts = {
            AZURE_SUBSCRIPTION_ID: {
                "default": SecurityContacts(
                    resource_id=resource_id,
                    emails="bad_email",
                    phone="",
                    alert_notifications_minimal_severity="High",
                    alert_notifications_state="On",
                    notified_roles=["Contributor"],
                    notified_roles_state="On",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact.defender_client",
            new=defender_client,
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
                == f"There is not another correct email configured for susbscription {AZURE_SUBSCRIPTION_ID}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "default"
            assert result[0].resource_id == resource_id

    def test_defender_additional_email_bad_separator(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.security_contacts = {
            AZURE_SUBSCRIPTION_ID: {
                "default": SecurityContacts(
                    resource_id=resource_id,
                    emails="test@test.es,   test@test.email.com",
                    phone="",
                    alert_notifications_minimal_severity="High",
                    alert_notifications_state="On",
                    notified_roles=["Contributor"],
                    notified_roles_state="On",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact.defender_client",
            new=defender_client,
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
                == f"There is not another correct email configured for susbscription {AZURE_SUBSCRIPTION_ID}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "default"
            assert result[0].resource_id == resource_id

    def test_defender_additional_email_good_format(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.security_contacts = {
            AZURE_SUBSCRIPTION_ID: {
                "default": SecurityContacts(
                    resource_id=resource_id,
                    emails="test@test.com",
                    phone="",
                    alert_notifications_minimal_severity="High",
                    alert_notifications_state="On",
                    notified_roles=["Contributor"],
                    notified_roles_state="On",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact.defender_client",
            new=defender_client,
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
                == f"There is another correct email configured for susbscription {AZURE_SUBSCRIPTION_ID}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "default"
            assert result[0].resource_id == resource_id

    def test_defender_additional_email_good_format_multiple_subdomains(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.security_contacts = {
            AZURE_SUBSCRIPTION_ID: {
                "default": SecurityContacts(
                    resource_id=resource_id,
                    emails="test@test.mail.es; bad_mail",
                    phone="",
                    alert_notifications_minimal_severity="High",
                    alert_notifications_state="On",
                    notified_roles=["Contributor"],
                    notified_roles_state="On",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact.defender_client",
            new=defender_client,
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
                == f"There is another correct email configured for susbscription {AZURE_SUBSCRIPTION_ID}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "default"
            assert result[0].resource_id == resource_id

    def test_defender_default_security_contact_not_found(self):
        defender_client = mock.MagicMock
        defender_client.security_contacts = {
            AZURE_SUBSCRIPTION_ID: {
                "default": SecurityContacts(
                    resource_id=f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Security/securityContacts/default",
                    emails="",
                    phone="",
                    alert_notifications_minimal_severity="",
                    alert_notifications_state="",
                    notified_roles=[""],
                    notified_roles_state="",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact.defender_client",
            new=defender_client,
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
                == f"There is not another correct email configured for susbscription {AZURE_SUBSCRIPTION_ID}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "default"
            assert (
                result[0].resource_id
                == f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Security/securityContacts/default"
            )
