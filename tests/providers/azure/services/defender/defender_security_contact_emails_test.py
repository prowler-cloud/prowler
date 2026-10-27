from unittest import mock

import pytest

from prowler.providers.azure.services.defender.defender_service import Defender
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


@pytest.mark.parametrize(
    "properties, expected_emails, expected_status",
    [
        ({}, [], "FAIL"),
        ({"emails": ""}, [], "FAIL"),
        ({"emails": " \t "}, [], "FAIL"),
        ({"emails": ";;"}, [], "FAIL"),
        ({"emails": "soc@example.com"}, ["soc@example.com"], "PASS"),
        (
            {"emails": "; soc@example.com ;; security@example.com; "},
            ["soc@example.com", "security@example.com"],
            "PASS",
        ),
    ],
)
def test_security_contact_email_collection(
    properties, expected_emails, expected_status
):
    """Only nonempty additional recipients should satisfy the email check."""
    provider = set_mocked_azure_provider()
    service = Defender.__new__(Defender)
    service.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
    service.region_config = provider.region_config
    resource_id = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Security/securityContacts/default"
    response = mock.MagicMock()
    response.json.return_value = {
        "value": [{"id": resource_id, "name": "default", "properties": properties}]
    }
    with mock.patch(
        "prowler.providers.azure.services.defender.defender_service.requests.get",
        return_value=response,
    ):
        service.security_contact_configurations = service._get_security_contacts(
            "token"
        )

    contact = service.security_contact_configurations[AZURE_SUBSCRIPTION_ID]["default"]
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=provider,
        ),
        mock.patch(
            "prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact.defender_client",
            new=service,
        ),
    ):
        from prowler.providers.azure.services.defender.defender_additional_email_configured_with_a_security_contact.defender_additional_email_configured_with_a_security_contact import (
            defender_additional_email_configured_with_a_security_contact,
        )

        findings = (
            defender_additional_email_configured_with_a_security_contact().execute()
        )

    assert len(findings) == 1
    assert findings[0].status == expected_status
    assert contact.emails == expected_emails
    assert findings[0].resource_id == resource_id
    assert findings[0].subscription == AZURE_SUBSCRIPTION_ID
