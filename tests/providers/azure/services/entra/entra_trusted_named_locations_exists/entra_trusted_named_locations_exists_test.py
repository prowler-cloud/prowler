from unittest import mock

from tests.providers.azure.azure_fixtures import DOMAIN, set_mocked_azure_provider


class Test_entra_trusted_named_locations_exists:
    def test_entra_no_tenants(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_trusted_named_locations_exists.entra_trusted_named_locations_exists.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_trusted_named_locations_exists.entra_trusted_named_locations_exists import (
                entra_trusted_named_locations_exists,
            )

            entra_client.named_locations = {}

            check = entra_trusted_named_locations_exists()
            result = check.execute()
            assert len(result) == 0

    def test_entra_tenant_empty(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_trusted_named_locations_exists.entra_trusted_named_locations_exists.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_trusted_named_locations_exists.entra_trusted_named_locations_exists import (
                entra_trusted_named_locations_exists,
            )

            entra_client.named_locations = {DOMAIN: {}}

            check = entra_trusted_named_locations_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "There is no trusted location with IP ranges defined."
            )
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Named Locations"
            assert result[0].resource_id == "Named Locations"

    def test_entra_named_location_with_ip_ranges(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_trusted_named_locations_exists.entra_trusted_named_locations_exists.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_service import (
                NamedLocation,
            )
            from prowler.providers.azure.services.entra.entra_trusted_named_locations_exists.entra_trusted_named_locations_exists import (
                entra_trusted_named_locations_exists,
            )

            entra_client.named_locations = {
                DOMAIN: {
                    "location_id": NamedLocation(
                        name="Test Location",
                        ip_ranges_addresses=["192.168.0.1/24"],
                        is_trusted=True,
                    )
                }
            }

            check = entra_trusted_named_locations_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Exits trusted location with trusted IP ranges, this IPs ranges are: ['192.168.0.1/24']"
            )
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Test Location"
            assert result[0].resource_id == "location_id"

    def test_entra_named_location_without_ip_ranges(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_trusted_named_locations_exists.entra_trusted_named_locations_exists.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_service import (
                NamedLocation,
            )
            from prowler.providers.azure.services.entra.entra_trusted_named_locations_exists.entra_trusted_named_locations_exists import (
                entra_trusted_named_locations_exists,
            )

            entra_client.named_locations = {
                DOMAIN: {
                    "location_id": NamedLocation(
                        name="Test Location", ip_ranges_addresses=[], is_trusted=True
                    )
                }
            }

            check = entra_trusted_named_locations_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "There is no trusted location with IP ranges defined."
            )
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Test Location"
            assert result[0].resource_id == "location_id"

    def test_entra_new_named_location_with_ip_ranges_not_trusted(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_trusted_named_locations_exists.entra_trusted_named_locations_exists.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_service import (
                NamedLocation,
            )
            from prowler.providers.azure.services.entra.entra_trusted_named_locations_exists.entra_trusted_named_locations_exists import (
                entra_trusted_named_locations_exists,
            )

            entra_client.named_locations = {
                DOMAIN: {
                    "location_id": NamedLocation(
                        name="Test Location",
                        ip_ranges_addresses=["192.168.0.1/24"],
                        is_trusted=False,
                    )
                }
            }

            check = entra_trusted_named_locations_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "There is no trusted location with IP ranges defined."
            )
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Test Location"
            assert result[0].resource_id == "location_id"
