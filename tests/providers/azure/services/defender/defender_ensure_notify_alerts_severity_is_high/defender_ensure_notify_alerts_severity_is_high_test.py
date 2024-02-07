from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import SecurityContacts
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_defender_ensure_notify_alerts_severity_is_high:
    def test_defender_no_subscriptions(self):
        defender_client = mock.MagicMock
        defender_client.security_contacts = {}

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_notify_alerts_severity_is_high.defender_ensure_notify_alerts_severity_is_high.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_notify_alerts_severity_is_high.defender_ensure_notify_alerts_severity_is_high import (
                defender_ensure_notify_alerts_severity_is_high,
            )

            check = defender_ensure_notify_alerts_severity_is_high()
            result = check.execute()
            assert len(result) == 0

    def test_defender_severity_alerts_low(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.security_contacts = {
            AZURE_SUBSCRIPTION: {
                "default": SecurityContacts(
                    resource_id=resource_id,
                    emails="",
                    phone="",
                    alert_notifications_minimal_severity="Low",
                    alert_notifications_state="On",
                    notified_roles=["Contributor"],
                    notified_roles_state="On",
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_notify_alerts_severity_is_high.defender_ensure_notify_alerts_severity_is_high.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_notify_alerts_severity_is_high.defender_ensure_notify_alerts_severity_is_high import (
                defender_ensure_notify_alerts_severity_is_high,
            )

            check = defender_ensure_notify_alerts_severity_is_high()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Notifiy alerts are not enabled for severity high in susbscription {AZURE_SUBSCRIPTION}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == "default"
            assert result[0].resource_id == resource_id

    def test_defender_severity_alerts_high(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.security_contacts = {
            AZURE_SUBSCRIPTION: {
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
            "prowler.providers.azure.services.defender.defender_ensure_notify_alerts_severity_is_high.defender_ensure_notify_alerts_severity_is_high.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_notify_alerts_severity_is_high.defender_ensure_notify_alerts_severity_is_high import (
                defender_ensure_notify_alerts_severity_is_high,
            )

            check = defender_ensure_notify_alerts_severity_is_high()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Notifiy alerts are enabled for severity high in susbscription {AZURE_SUBSCRIPTION}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == "default"
            assert result[0].resource_id == resource_id

    def test_defender_default_security_contact_not_found(self):
        defender_client = mock.MagicMock
        defender_client.security_contacts = {
            AZURE_SUBSCRIPTION: {
                "default": SecurityContacts(
                    resource_id=f"/subscriptions/{AZURE_SUBSCRIPTION}/providers/Microsoft.Security/securityContacts/default",
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
            "prowler.providers.azure.services.defender.defender_ensure_notify_alerts_severity_is_high.defender_ensure_notify_alerts_severity_is_high.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_notify_alerts_severity_is_high.defender_ensure_notify_alerts_severity_is_high import (
                defender_ensure_notify_alerts_severity_is_high,
            )

            check = defender_ensure_notify_alerts_severity_is_high()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Notifiy alerts are not enabled for severity high in susbscription {AZURE_SUBSCRIPTION}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == "default"
            assert (
                result[0].resource_id
                == f"/subscriptions/{AZURE_SUBSCRIPTION}/providers/Microsoft.Security/securityContacts/default"
            )
