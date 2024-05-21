from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import DOMAIN, set_mocked_azure_provider


class Test_entra_users_cannot_create_microsoft_365_groups:
    def test_entra_no_tenant(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_users_cannot_create_microsoft_365_groups.entra_users_cannot_create_microsoft_365_groups.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_users_cannot_create_microsoft_365_groups.entra_users_cannot_create_microsoft_365_groups import (
                entra_users_cannot_create_microsoft_365_groups,
            )

            entra_client.group_settings = {}

            check = entra_users_cannot_create_microsoft_365_groups()
            result = check.execute()
            assert len(result) == 0

    def test_entra_tenant_empty(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_users_cannot_create_microsoft_365_groups.entra_users_cannot_create_microsoft_365_groups.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_users_cannot_create_microsoft_365_groups.entra_users_cannot_create_microsoft_365_groups import (
                entra_users_cannot_create_microsoft_365_groups,
            )

            entra_client.group_settings = {DOMAIN: {}}

            check = entra_users_cannot_create_microsoft_365_groups()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "Users can create Microsoft 365 groups."
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Microsoft365 Groups"
            assert result[0].resource_id == "Microsoft365 Groups"

    def test_entra_users_cannot_create_microsoft_365_groups(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_users_cannot_create_microsoft_365_groups.entra_users_cannot_create_microsoft_365_groups.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_service import (
                GroupSetting,
            )
            from prowler.providers.azure.services.entra.entra_users_cannot_create_microsoft_365_groups.entra_users_cannot_create_microsoft_365_groups import (
                entra_users_cannot_create_microsoft_365_groups,
            )

            id = str(uuid4())
            template_id = str(uuid4())

            setting = mock.MagicMock
            setting.name = "EnableGroupCreation"
            setting.value = "false"

            entra_client.group_settings = {
                DOMAIN: {
                    id: GroupSetting(
                        name="Group.Unified",
                        template_id=template_id,
                        settings=[setting],
                    )
                }
            }

            check = entra_users_cannot_create_microsoft_365_groups()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended == "Users cannot create Microsoft 365 groups."
            )
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Microsoft365 Groups"
            assert result[0].resource_id == "Microsoft365 Groups"

    def test_entra_users_can_create_microsoft_365_groups(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_users_cannot_create_microsoft_365_groups.entra_users_cannot_create_microsoft_365_groups.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_service import (
                GroupSetting,
            )
            from prowler.providers.azure.services.entra.entra_users_cannot_create_microsoft_365_groups.entra_users_cannot_create_microsoft_365_groups import (
                entra_users_cannot_create_microsoft_365_groups,
            )

            id = str(uuid4())
            template_id = str(uuid4())

            setting = mock.MagicMock
            setting.name = "EnableGroupCreation"
            setting.value = "true"

            entra_client.group_settings = {
                DOMAIN: {
                    id: GroupSetting(
                        name="Group.Unified",
                        template_id=template_id,
                        settings=[setting],
                    )
                }
            }

            check = entra_users_cannot_create_microsoft_365_groups()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "Users can create Microsoft 365 groups."
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Microsoft365 Groups"
            assert result[0].resource_id == "Microsoft365 Groups"

    def test_entra_users_can_create_microsoft_365_groups_no_setting(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_users_cannot_create_microsoft_365_groups.entra_users_cannot_create_microsoft_365_groups.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_service import (
                GroupSetting,
            )
            from prowler.providers.azure.services.entra.entra_users_cannot_create_microsoft_365_groups.entra_users_cannot_create_microsoft_365_groups import (
                entra_users_cannot_create_microsoft_365_groups,
            )

            id = str(uuid4())
            template_id = str(uuid4())

            entra_client.group_settings = {
                DOMAIN: {
                    id: GroupSetting(
                        name="Group.Unified",
                        template_id=template_id,
                        settings=[],
                    )
                }
            }

            check = entra_users_cannot_create_microsoft_365_groups()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "Users can create Microsoft 365 groups."
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Microsoft365 Groups"
            assert result[0].resource_id == "Microsoft365 Groups"
