from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import (
    Defender_Security_Contacts,
)
from tests.providers.azure.azure_fixtures import AZURE_SUSCRIPTION


class Test_defender_ensure_notify_emails_to_owners:
    def test_defender_no_notify_emails(self):
        defender_client = mock.MagicMock
        defender_client.security_contacts = {}

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_notify_emails_to_owners.defender_ensure_notify_emails_to_owners.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_notify_emails_to_owners.defender_ensure_notify_emails_to_owners import (
                defender_ensure_notify_emails_to_owners,
            )

            check = defender_ensure_notify_emails_to_owners()
            result = check.execute()
            assert len(result) == 0

    def test_defender_no_notify_emails_to_owners(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.security_contacts = {
            AZURE_SUSCRIPTION: {
                "default": Defender_Security_Contacts(
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
            "prowler.providers.azure.services.defender.defender_ensure_notify_emails_to_owners.defender_ensure_notify_emails_to_owners.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_notify_emails_to_owners.defender_ensure_notify_emails_to_owners import (
                defender_ensure_notify_emails_to_owners,
            )

            check = defender_ensure_notify_emails_to_owners()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"The Owner role is not notified for subscription {AZURE_SUSCRIPTION}."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == "default"
            assert result[0].resource_id == resource_id

    def test_defender_notify_emails_to_owners_off(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.security_contacts = {
            AZURE_SUSCRIPTION: {
                "default": Defender_Security_Contacts(
                    resource_id=resource_id,
                    emails="",
                    phone="",
                    alert_notifications_minimal_severity="High",
                    alert_notifications_state="On",
                    notified_roles=["Owner", "Contributor"],
                    notified_roles_state="Off",
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_notify_emails_to_owners.defender_ensure_notify_emails_to_owners.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_notify_emails_to_owners.defender_ensure_notify_emails_to_owners import (
                defender_ensure_notify_emails_to_owners,
            )

            check = defender_ensure_notify_emails_to_owners()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"The Owner role is not notified for subscription {AZURE_SUSCRIPTION}."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == "default"
            assert result[0].resource_id == resource_id

    def test_defender_notify_emails_to_owners(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.security_contacts = {
            AZURE_SUSCRIPTION: {
                "default": Defender_Security_Contacts(
                    resource_id=resource_id,
                    emails="test@test.es",
                    phone="",
                    alert_notifications_minimal_severity="High",
                    alert_notifications_state="On",
                    notified_roles=["Owner", "Contributor"],
                    notified_roles_state="On",
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_notify_emails_to_owners.defender_ensure_notify_emails_to_owners.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_notify_emails_to_owners.defender_ensure_notify_emails_to_owners import (
                defender_ensure_notify_emails_to_owners,
            )

            check = defender_ensure_notify_emails_to_owners()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"The Owner role is notified for subscription {AZURE_SUSCRIPTION}."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == "default"
            assert result[0].resource_id == resource_id
