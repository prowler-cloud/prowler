from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.storage.storage_service import (
    Account,
    NetworkRuleSet,
    ReplicationSettings,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_storage_geo_redundant_enabled:
    def test_no_storage_accounts(self):
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled import (
                storage_geo_redundant_enabled,
            )

            check = storage_geo_redundant_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_storage_account_standard_grs_enabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account GRS"
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="None",
                    minimum_tls_version="TLS1_2",
                    private_endpoint_connections=[],
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    replication_settings=ReplicationSettings.STANDARD_GRS,
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled import (
                storage_geo_redundant_enabled,
            )

            check = storage_geo_redundant_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} has Geo-redundant storage Standard_GRS enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].location == "westeurope"

    def test_storage_account_standard_ragrs_enabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account RAGRS"
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="None",
                    minimum_tls_version="TLS1_2",
                    private_endpoint_connections=[],
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    replication_settings=ReplicationSettings.STANDARD_RAGRS,
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled import (
                storage_geo_redundant_enabled,
            )

            check = storage_geo_redundant_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} has Geo-redundant storage Standard_RAGRS enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].location == "westeurope"

    def test_storage_account_standard_gzrs_enabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account GZRS"
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="None",
                    minimum_tls_version="TLS1_2",
                    private_endpoint_connections=[],
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    replication_settings=ReplicationSettings.STANDARD_GZRS,
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled import (
                storage_geo_redundant_enabled,
            )

            check = storage_geo_redundant_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} has Geo-redundant storage Standard_GZRS enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].location == "westeurope"

    def test_storage_account_standard_ragzrs_enabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account RAGZRS"
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="None",
                    minimum_tls_version="TLS1_2",
                    private_endpoint_connections=[],
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    replication_settings=ReplicationSettings.STANDARD_RAGZRS,
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled import (
                storage_geo_redundant_enabled,
            )

            check = storage_geo_redundant_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} has Geo-redundant storage Standard_RAGZRS enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].location == "westeurope"

    def test_storage_account_standard_lrs_disabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account LRS"
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="None",
                    minimum_tls_version="TLS1_2",
                    private_endpoint_connections=[],
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    replication_settings=ReplicationSettings.STANDARD_LRS,
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled import (
                storage_geo_redundant_enabled,
            )

            check = storage_geo_redundant_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} does not have Geo-redundant storage enabled, it has Standard_LRS instead."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].location == "westeurope"

    def test_storage_account_standard_zrs_disabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account ZRS"
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="None",
                    minimum_tls_version="TLS1_2",
                    private_endpoint_connections=[],
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    replication_settings=ReplicationSettings.STANDARD_ZRS,
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled import (
                storage_geo_redundant_enabled,
            )

            check = storage_geo_redundant_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} does not have Geo-redundant storage enabled, it has Standard_ZRS instead."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].location == "westeurope"

    def test_storage_account_premium_lrs_disabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account Premium LRS"
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="None",
                    minimum_tls_version="TLS1_2",
                    private_endpoint_connections=[],
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    replication_settings=ReplicationSettings.PREMIUM_LRS,
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled import (
                storage_geo_redundant_enabled,
            )

            check = storage_geo_redundant_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} does not have Geo-redundant storage enabled, it has Premium_LRS instead."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].location == "westeurope"

    def test_storage_account_premium_zrs_disabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account Premium ZRS"
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="None",
                    minimum_tls_version="TLS1_2",
                    private_endpoint_connections=[],
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    replication_settings=ReplicationSettings.PREMIUM_ZRS,
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled import (
                storage_geo_redundant_enabled,
            )

            check = storage_geo_redundant_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} does not have Geo-redundant storage enabled, it has Premium_ZRS instead."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].location == "westeurope"
