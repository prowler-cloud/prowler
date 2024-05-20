from unittest import mock
from uuid import uuid4

from prowler.providers.azure.config import VIRTUAL_MACHINE_ADMINISTRATOR_LOGIN_ROLE_ID
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    DOMAIN,
    set_mocked_azure_provider,
)


class Test_iam_assignment_priviledge_access_vm_has_mfa:
    def test_iam_no_roles(self):
        iam_client = mock.MagicMock
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.iam_client",
            new=iam_client,
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
        role_assigment_id = str(uuid4())
        entra_client = mock.MagicMock
        user_id = str(uuid4())

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.iam_client",
            new=iam_client,
        ):
            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ), mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.entra_client",
                new=entra_client,
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
                            authentication_methods=[
                                "Password",
                                "MicrosoftAuthenticator",
                            ],
                        )
                    }
                }

                check = entra_user_with_vm_access_has_mfa()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"User test can access VMs in subscription {AZURE_SUBSCRIPTION_ID} but it has MFA."
                )
                assert result[0].subscription == AZURE_SUBSCRIPTION_ID
                assert result[0].resource_name == f"test@{DOMAIN}"
                assert result[0].resource_id == user_id

    def test_entra_user_with_vm_access_has_mfa_no_mfa(self):
        iam_client = mock.MagicMock
        role_assigment_id = str(uuid4())
        entra_client = mock.MagicMock
        user_id = str(uuid4())

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.iam_client",
            new=iam_client,
        ):
            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ), mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.entra_client",
                new=entra_client,
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
                            role_id=VIRTUAL_MACHINE_ADMINISTRATOR_LOGIN_ROLE_ID,
                            agent_type="User",
                            agent_id=user_id,
                        )
                    }
                }

                entra_client.users = {
                    DOMAIN: {
                        f"test@{DOMAIN}": User(
                            id=user_id, name="test", authentication_methods=["Password"]
                        )
                    }
                }

                check = entra_user_with_vm_access_has_mfa()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"User test without MFA can access VMs in subscription {AZURE_SUBSCRIPTION_ID}"
                )
                assert result[0].subscription == AZURE_SUBSCRIPTION_ID
                assert result[0].resource_name == f"test@{DOMAIN}"
                assert result[0].resource_id == user_id

    def test_entra_user_with_vm_access_has_mfa_no_user(self):
        iam_client = mock.MagicMock
        role_assigment_id = str(uuid4())
        entra_client = mock.MagicMock
        user_id = str(uuid4())

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.iam_client",
            new=iam_client,
        ):
            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ), mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.entra_client",
                new=entra_client,
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
        role_assigment_id = str(uuid4())
        entra_client = mock.MagicMock
        user_id = str(uuid4())

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.iam_client",
            new=iam_client,
        ):
            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ), mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_vm_access_has_mfa.entra_user_with_vm_access_has_mfa.entra_client",
                new=entra_client,
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
                            authentication_methods=[
                                "Password",
                                "MicrosoftAuthenticator",
                            ],
                        )
                    }
                }

                check = entra_user_with_vm_access_has_mfa()
                result = check.execute()
                assert len(result) == 0
