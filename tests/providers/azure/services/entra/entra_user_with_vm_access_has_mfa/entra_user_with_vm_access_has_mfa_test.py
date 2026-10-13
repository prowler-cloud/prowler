from unittest import mock
from uuid import uuid4

from prowler.providers.azure.config import VIRTUAL_MACHINE_ADMINISTRATOR_LOGIN_ROLE_ID
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    DOMAIN,
    TENANT_IDS,
    set_mocked_azure_provider,
)


class Test_iam_assignment_priviledge_access_vm_has_mfa:
    def test_iam_no_roles(self):
        iam_client = mock.MagicMock
        iam_client.resource_groups = {}
        iam_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        entra_client = mock.MagicMock
        entra_client.resource_groups = {}
        entra_client.users_retrieval_errors = {}
        entra_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.entra_client",
                new=entra_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa import (
                entra_user_with_vm_access_has_mfa,
            )

            iam_client.role_assignments = {}
            entra_client.users = {}

            check = entra_user_with_vm_access_has_mfa()
            result = check.execute()
            assert len(result) == 0

    def test_entra_user_with_vm_access_has_mfa(self):
        iam_client = mock.MagicMock
        iam_client.resource_groups = {}
        iam_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        role_assigment_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.resource_groups = {}
        entra_client.users_retrieval_errors = {}
        entra_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        user_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.iam_client",
                new=iam_client,
            ),
        ):
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=set_mocked_azure_provider(),
                ),
                mock.patch(
                    "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.entra_client",
                    new=entra_client,
                ),
            ):
                from prowler.providers.azure.services.entra.entra_service import User
                from prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa import (
                    entra_user_with_vm_access_has_mfa,
                )
                from prowler.providers.azure.services.iam.iam_service import (
                    RoleAssignment,
                )

                iam_client.role_assignments = {
                    AZURE_SUBSCRIPTION_ID: {
                        role_assigment_id: RoleAssignment(
                            id=role_assigment_id,
                            name="test",
                            scope=AZURE_SUBSCRIPTION_ID,
                            role_id=VIRTUAL_MACHINE_ADMINISTRATOR_LOGIN_ROLE_ID,
                            agent_type="User",
                            agent_id=user_id,
                        )
                    }
                }

                entra_client.users = {
                    DOMAIN: {
                        f"test@{DOMAIN}": User(
                            id=user_id,
                            name="test",
                            is_mfa_capable=True,
                        )
                    }
                }

                check = entra_user_with_vm_access_has_mfa()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"User test can access VMs in subscription {AZURE_SUBSCRIPTION_DISPLAY} but it has MFA."
                )
                assert result[0].subscription == AZURE_SUBSCRIPTION_ID
                assert result[0].resource_name == "test"
                assert result[0].resource_id == user_id

    def test_entra_user_with_vm_access_has_mfa_no_mfa(self):
        iam_client = mock.MagicMock
        iam_client.resource_groups = {}
        iam_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        role_assigment_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.resource_groups = {}
        entra_client.users_retrieval_errors = {}
        entra_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        user_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.iam_client",
                new=iam_client,
            ),
        ):
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=set_mocked_azure_provider(),
                ),
                mock.patch(
                    "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.entra_client",
                    new=entra_client,
                ),
            ):
                from prowler.providers.azure.services.entra.entra_service import User
                from prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa import (
                    entra_user_with_vm_access_has_mfa,
                )
                from prowler.providers.azure.services.iam.iam_service import (
                    RoleAssignment,
                )

                iam_client.role_assignments = {
                    AZURE_SUBSCRIPTION_ID: {
                        role_assigment_id: RoleAssignment(
                            id=role_assigment_id,
                            name="test",
                            scope=AZURE_SUBSCRIPTION_ID,
                            role_id=VIRTUAL_MACHINE_ADMINISTRATOR_LOGIN_ROLE_ID,
                            agent_type="User",
                            agent_id=user_id,
                        )
                    }
                }

                entra_client.users = {
                    DOMAIN: {
                        f"test@{DOMAIN}": User(
                            id=user_id,
                            name="test",
                            is_mfa_capable=False,
                        )
                    }
                }

                check = entra_user_with_vm_access_has_mfa()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"User test without MFA can access VMs in subscription {AZURE_SUBSCRIPTION_DISPLAY}"
                )
                assert result[0].subscription == AZURE_SUBSCRIPTION_ID
                assert result[0].resource_name == "test"
                assert result[0].resource_id == user_id

    def test_entra_user_with_vm_access_has_mfa_no_user(self):
        iam_client = mock.MagicMock
        iam_client.resource_groups = {}
        iam_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        role_assigment_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.resource_groups = {}
        entra_client.users_retrieval_errors = {}
        entra_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        user_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.iam_client",
                new=iam_client,
            ),
        ):
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=set_mocked_azure_provider(),
                ),
                mock.patch(
                    "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.entra_client",
                    new=entra_client,
                ),
            ):
                from prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa import (
                    entra_user_with_vm_access_has_mfa,
                )
                from prowler.providers.azure.services.iam.iam_service import (
                    RoleAssignment,
                )

                iam_client.role_assignments = {
                    AZURE_SUBSCRIPTION_ID: {
                        role_assigment_id: RoleAssignment(
                            id=role_assigment_id,
                            name="test",
                            scope=AZURE_SUBSCRIPTION_ID,
                            role_id=VIRTUAL_MACHINE_ADMINISTRATOR_LOGIN_ROLE_ID,
                            agent_type="User",
                            agent_id=user_id,
                        )
                    }
                }

                entra_client.users = {DOMAIN: {}}

                check = entra_user_with_vm_access_has_mfa()
                result = check.execute()
                assert len(result) == 0

    def test_entra_user_with_vm_access_has_mfa_no_role(self):
        iam_client = mock.MagicMock
        iam_client.resource_groups = {}
        iam_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        role_assigment_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.resource_groups = {}
        entra_client.users_retrieval_errors = {}
        entra_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        user_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.iam_client",
                new=iam_client,
            ),
        ):
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=set_mocked_azure_provider(),
                ),
                mock.patch(
                    "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.entra_client",
                    new=entra_client,
                ),
            ):
                from prowler.providers.azure.services.entra.entra_service import User
                from prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa import (
                    entra_user_with_vm_access_has_mfa,
                )
                from prowler.providers.azure.services.iam.iam_service import (
                    RoleAssignment,
                )

                iam_client.role_assignments = {
                    AZURE_SUBSCRIPTION_ID: {
                        role_assigment_id: RoleAssignment(
                            id=role_assigment_id,
                            name="test",
                            scope=AZURE_SUBSCRIPTION_ID,
                            role_id=str(uuid4()),
                            agent_type="User",
                            agent_id=user_id,
                        )
                    }
                }

                entra_client.users = {
                    DOMAIN: {
                        f"test@{DOMAIN}": User(
                            id=user_id,
                            name="test",
                            is_mfa_capable=True,
                        )
                    }
                }

                check = entra_user_with_vm_access_has_mfa()
                result = check.execute()
                assert len(result) == 0

    def test_entra_users_retrieval_error_reports_single_manual(self):
        """Graph could not return the tenant's users -> one tenant-level MANUAL."""
        iam_client = mock.MagicMock
        iam_client.resource_groups = {}
        iam_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        entra_client = mock.MagicMock
        entra_client.resource_groups = {}
        entra_client.users_retrieval_errors = {DOMAIN: "ODataError HTTP 503"}
        entra_client.tenant_ids = [TENANT_IDS[0]]
        entra_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.entra_client",
                new=entra_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa import (
                entra_user_with_vm_access_has_mfa,
            )

            iam_client.role_assignments = {}
            entra_client.users = {DOMAIN: {}}

            result = entra_user_with_vm_access_has_mfa().execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "did not return the tenant's users" in result[0].status_extended
            assert "503" in result[0].status_extended
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_id == TENANT_IDS[0]
