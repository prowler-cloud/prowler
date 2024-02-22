from unittest.mock import patch

from prowler.providers.azure.services.keyvault.keyvault_service import (
    Key,
    KeyVault,
    KeyVaultInfo,
    Secret,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_audit_info,
)


def mock_keyvault_get_key_vaults(_, __):
    keyvault_info = KeyVaultInfo(
        id="id",
        name="name",
        location="location",
        resource_group="resource_group",
        properties=None,
        keys=[
            Key(
                id="id",
                name="name",
                enabled=True,
                location="location",
                attributes=None,
                rotation_policy=None,
            )
        ],
        secrets=[
            Secret(
                id="id",
                name="name",
                enabled=True,
                location="location",
                attributes=None,
            )
        ],
    )
    return {AZURE_SUBSCRIPTION: [keyvault_info]}


@patch(
    "prowler.providers.azure.services.keyvault.keyvault_service.KeyVault.__get_key_vaults__",
    new=mock_keyvault_get_key_vaults,
)
class Test_keyvault_service:
    def test__get_client__(self):
        keyvault = KeyVault(set_mocked_azure_audit_info())
        assert (
            keyvault.clients[AZURE_SUBSCRIPTION].__class__.__name__
            == "KeyVaultManagementClient"
        )

    def test__get_key_vaults__(self):
        keyvault = KeyVault(set_mocked_azure_audit_info())
        assert (
            keyvault.key_vaults[AZURE_SUBSCRIPTION][0].__class__.__name__
            == "KeyVaultInfo"
        )
        assert keyvault.key_vaults[AZURE_SUBSCRIPTION][0].id == "id"
        assert keyvault.key_vaults[AZURE_SUBSCRIPTION][0].name == "name"
        assert keyvault.key_vaults[AZURE_SUBSCRIPTION][0].location == "location"
        assert (
            keyvault.key_vaults[AZURE_SUBSCRIPTION][0].resource_group
            == "resource_group"
        )
        assert keyvault.key_vaults[AZURE_SUBSCRIPTION][0].properties is None

    def test__get_keys__(self):
        keyvault = KeyVault(set_mocked_azure_audit_info())
        assert (
            keyvault.key_vaults[AZURE_SUBSCRIPTION][0].keys[0].__class__.__name__
            == "Key"
        )
        assert keyvault.key_vaults[AZURE_SUBSCRIPTION][0].keys[0].id == "id"
        assert keyvault.key_vaults[AZURE_SUBSCRIPTION][0].keys[0].name == "name"
        assert keyvault.key_vaults[AZURE_SUBSCRIPTION][0].keys[0].enabled is True
        assert keyvault.key_vaults[AZURE_SUBSCRIPTION][0].keys[0].location == "location"
        assert keyvault.key_vaults[AZURE_SUBSCRIPTION][0].keys[0].attributes is None
        assert (
            keyvault.key_vaults[AZURE_SUBSCRIPTION][0].keys[0].rotation_policy is None
        )

    def test__get_secrets__(self):
        keyvault = KeyVault(set_mocked_azure_audit_info())
        assert (
            keyvault.key_vaults[AZURE_SUBSCRIPTION][0].secrets[0].__class__.__name__
            == "Secret"
        )
        assert keyvault.key_vaults[AZURE_SUBSCRIPTION][0].secrets[0].id == "id"
        assert keyvault.key_vaults[AZURE_SUBSCRIPTION][0].secrets[0].name == "name"
        assert keyvault.key_vaults[AZURE_SUBSCRIPTION][0].secrets[0].enabled is True
        assert (
            keyvault.key_vaults[AZURE_SUBSCRIPTION][0].secrets[0].location == "location"
        )
        assert keyvault.key_vaults[AZURE_SUBSCRIPTION][0].secrets[0].attributes is None
