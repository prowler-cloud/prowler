from unittest import mock

from prowler.providers.m365.services.entra.entra_service import NamedLocation
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_trusted_named_location_exists.entra_conditional_access_trusted_named_location_exists"


class Test_entra_conditional_access_trusted_named_location_exists:
    def _run(self, named_locations):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_trusted_named_location_exists.entra_conditional_access_trusted_named_location_exists import (
                entra_conditional_access_trusted_named_location_exists,
            )

            entra_client.named_locations = named_locations
            return entra_conditional_access_trusted_named_location_exists().execute()

    def test_no_locations(self):
        result = self._run([])
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_trusted_ip_location(self):
        result = self._run(
            [
                NamedLocation(
                    id="loc1",
                    display_name="Corp",
                    is_trusted=True,
                    is_ip_location=True,
                    ip_ranges_count=2,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_untrusted_ip_location(self):
        result = self._run(
            [
                NamedLocation(
                    id="loc1",
                    is_trusted=False,
                    is_ip_location=True,
                    ip_ranges_count=2,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_trusted_but_no_ranges(self):
        result = self._run(
            [
                NamedLocation(
                    id="loc1",
                    is_trusted=True,
                    is_ip_location=True,
                    ip_ranges_count=0,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
