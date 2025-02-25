from unittest import mock
from uuid import uuid4

from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


class Test_admincenter_settings_password_never_expire:
    def test_admincenter_no_domains(self):
        admincenter_client = mock.MagicMock
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.admincenter.admincenter_settings_password_never_expire.admincenter_settings_password_never_expire.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.microsoft365.services.admincenter.admincenter_settings_password_never_expire.admincenter_settings_password_never_expire import (
                admincenter_settings_password_never_expire,
            )

            admincenter_client.domains = {}

            check = admincenter_settings_password_never_expire()
            result = check.execute()
            assert len(result) == 0

    def test_admincenter_domain_password_expire(self):
        admincenter_client = mock.MagicMock
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.admincenter.admincenter_settings_password_never_expire.admincenter_settings_password_never_expire.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.microsoft365.services.admincenter.admincenter_service import (
                Domain,
            )
            from prowler.providers.microsoft365.services.admincenter.admincenter_settings_password_never_expire.admincenter_settings_password_never_expire import (
                admincenter_settings_password_never_expire,
            )

            id_domain = str(uuid4())

            admincenter_client.domains = {
                id_domain: Domain(id=id_domain, password_validity_period=5),
            }

            check = admincenter_settings_password_never_expire()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Domain {id_domain} does not have a Password never expires policy."
            )
            assert result[0].resource == {
                "id": id_domain,
                "password_validity_period": 5,
            }
            assert result[0].resource_name == id_domain
            assert result[0].resource_id == id_domain
            assert result[0].location == "global"

    def test_admincenter_password_not_expire(self):
        admincenter_client = mock.MagicMock
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.admincenter.admincenter_settings_password_never_expire.admincenter_settings_password_never_expire.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.microsoft365.services.admincenter.admincenter_service import (
                Domain,
            )
            from prowler.providers.microsoft365.services.admincenter.admincenter_settings_password_never_expire.admincenter_settings_password_never_expire import (
                admincenter_settings_password_never_expire,
            )

            id_domain = str(uuid4())

            admincenter_client.domains = {
                id_domain: Domain(id=id_domain, password_validity_period=2147483647),
            }

            check = admincenter_settings_password_never_expire()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Domain {id_domain} Password policy is set to never expire."
            )
            assert result[0].resource == {
                "id": id_domain,
                "password_validity_period": 2147483647,
            }
            assert result[0].resource_name == id_domain
            assert result[0].resource_id == id_domain
            assert result[0].location == "global"
