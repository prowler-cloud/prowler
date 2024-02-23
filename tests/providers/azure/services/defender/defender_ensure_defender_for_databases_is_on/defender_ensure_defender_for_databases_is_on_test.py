from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import Pricing
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_defender_ensure_defender_for_databases_is_on:
    def test_defender_no_databases(self):
        defender_client = mock.MagicMock
        defender_client.pricings = {}

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_defender_for_databases_is_on.defender_ensure_defender_for_databases_is_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_defender_for_databases_is_on.defender_ensure_defender_for_databases_is_on import (
                defender_ensure_defender_for_databases_is_on,
            )

            check = defender_ensure_defender_for_databases_is_on()
            result = check.execute()
            assert len(result) == 0

    def test_defender_databases_sql_servers(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.pricings = {
            AZURE_SUBSCRIPTION: {
                "SqlServers": Pricing(
                    resource_id=resource_id,
                    pricing_tier="Standard",
                    free_trial_remaining_time=0,
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_defender_for_databases_is_on.defender_ensure_defender_for_databases_is_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_defender_for_databases_is_on.defender_ensure_defender_for_databases_is_on import (
                defender_ensure_defender_for_databases_is_on,
            )

            check = defender_ensure_defender_for_databases_is_on()
            result = check.execute()
            assert len(result) == 0

    def test_defender_databases_sql_server_virtual_machines(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.pricings = {
            AZURE_SUBSCRIPTION: {
                "SqlServerVirtualMachines": Pricing(
                    resource_id=resource_id,
                    pricing_tier="Standard",
                    free_trial_remaining_time=0,
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_defender_for_databases_is_on.defender_ensure_defender_for_databases_is_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_defender_for_databases_is_on.defender_ensure_defender_for_databases_is_on import (
                defender_ensure_defender_for_databases_is_on,
            )

            check = defender_ensure_defender_for_databases_is_on()
            result = check.execute()
            assert len(result) == 0

    def test_defender_databases_open_source_relation_databases(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.pricings = {
            AZURE_SUBSCRIPTION: {
                "OpenSourceRelationalDatabases": Pricing(
                    resource_id=resource_id,
                    pricing_tier="Standard",
                    free_trial_remaining_time=0,
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_defender_for_databases_is_on.defender_ensure_defender_for_databases_is_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_defender_for_databases_is_on.defender_ensure_defender_for_databases_is_on import (
                defender_ensure_defender_for_databases_is_on,
            )

            check = defender_ensure_defender_for_databases_is_on()
            result = check.execute()
            assert len(result) == 0

    def test_defender_databases_cosmosdbs(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.pricings = {
            AZURE_SUBSCRIPTION: {
                "CosmosDbs": Pricing(
                    resource_id=resource_id,
                    pricing_tier="Standard",
                    free_trial_remaining_time=0,
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_defender_for_databases_is_on.defender_ensure_defender_for_databases_is_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_defender_for_databases_is_on.defender_ensure_defender_for_databases_is_on import (
                defender_ensure_defender_for_databases_is_on,
            )

            check = defender_ensure_defender_for_databases_is_on()
            result = check.execute()
            assert len(result) == 0

    def test_defender_databases_all_standard(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.pricings = {
            AZURE_SUBSCRIPTION: {
                "SqlServers": Pricing(
                    resource_id=resource_id,
                    pricing_tier="Standard",
                    free_trial_remaining_time=0,
                ),
                "SqlServerVirtualMachines": Pricing(
                    resource_id=resource_id,
                    pricing_tier="Standard",
                    free_trial_remaining_time=0,
                ),
                "OpenSourceRelationalDatabases": Pricing(
                    resource_id=resource_id,
                    pricing_tier="Standard",
                    free_trial_remaining_time=0,
                ),
                "CosmosDbs": Pricing(
                    resource_id=resource_id,
                    pricing_tier="Standard",
                    free_trial_remaining_time=0,
                ),
            },
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_defender_for_databases_is_on.defender_ensure_defender_for_databases_is_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_defender_for_databases_is_on.defender_ensure_defender_for_databases_is_on import (
                defender_ensure_defender_for_databases_is_on,
            )

            check = defender_ensure_defender_for_databases_is_on()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Defender plan Defender for Databases from subscription {AZURE_SUBSCRIPTION} is set to ON (pricing tier standard)."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == "Defender plan Databases"
            assert result[0].resource_id == resource_id

    def test_defender_databases_cosmosdb_not_standard(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.pricings = {
            AZURE_SUBSCRIPTION: {
                "SqlServers": Pricing(
                    resource_id=resource_id,
                    pricing_tier="Standard",
                    free_trial_remaining_time=0,
                ),
                "SqlServerVirtualMachines": Pricing(
                    resource_id=resource_id,
                    pricing_tier="Standard",
                    free_trial_remaining_time=0,
                ),
                "OpenSourceRelationalDatabases": Pricing(
                    resource_id=resource_id,
                    pricing_tier="Standard",
                    free_trial_remaining_time=0,
                ),
                "CosmosDbs": Pricing(
                    resource_id=resource_id,
                    pricing_tier="Not Standard",
                    free_trial_remaining_time=0,
                ),
            },
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_defender_for_databases_is_on.defender_ensure_defender_for_databases_is_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_defender_for_databases_is_on.defender_ensure_defender_for_databases_is_on import (
                defender_ensure_defender_for_databases_is_on,
            )

            check = defender_ensure_defender_for_databases_is_on()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Defender plan Defender for Databases from subscription {AZURE_SUBSCRIPTION} is set to OFF (pricing tier not standard)."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == "Defender plan Databases"
            assert result[0].resource_id == resource_id
