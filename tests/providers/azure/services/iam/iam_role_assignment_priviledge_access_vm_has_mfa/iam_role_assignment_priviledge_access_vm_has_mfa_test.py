from unittest import mock
from uuid import uuid4

from prowler.providers.azure.config import VIRTUAL_MACHINE_ADMINISTRATOR_LOGIN_ROLE_ID
from prowler.providers.azure.services.entra.entra_service import User
from prowler.providers.azure.services.iam.iam_service import RoleAssignment
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION, DOMAIN


class Test_iam_assignment_priviledge_access_vm_has_mfa:
    def test_iam_no_roles(self):
        iam_client = mock.MagicMock
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.azure.services.iam.iam_role_assignment_priviledge_access_vm_has_mfa.iam_role_assignment_priviledge_access_vm_has_mfa.iam_client",
            new=iam_client,
        ):
            from prowler.providers.azure.services.iam.iam_role_assignment_priviledge_access_vm_has_mfa.iam_role_assignment_priviledge_access_vm_has_mfa import (
                iam_role_assignment_priviledge_access_vm_has_mfa,
            )

            iam_client.role_assignments = {}
            entra_client.users = {}

            check = iam_role_assignment_priviledge_access_vm_has_mfa()
            result = check.execute()
            assert len(result) == 0

    def test_iam_role_assignment_priviledge_access_vm_has_mfa(self):
        iam_client = mock.MagicMock
        role_assigment_id = str(uuid4())
        entra_client = mock.MagicMock
        user_id = str(uuid4())

        with mock.patch(
            "prowler.providers.azure.services.iam.iam_role_assignment_priviledge_access_vm_has_mfa.iam_role_assignment_priviledge_access_vm_has_mfa.iam_client",
            new=iam_client,
        ):
            with mock.patch(
                "prowler.providers.azure.services.iam.iam_role_assignment_priviledge_access_vm_has_mfa.iam_role_assignment_priviledge_access_vm_has_mfa.entra_client",
                new=entra_client,
            ):
                from prowler.providers.azure.services.iam.iam_role_assignment_priviledge_access_vm_has_mfa.iam_role_assignment_priviledge_access_vm_has_mfa import (
                    iam_role_assignment_priviledge_access_vm_has_mfa,
                )

                iam_client.role_assignments = {
                    AZURE_SUBSCRIPTION: {
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

                check = iam_role_assignment_priviledge_access_vm_has_mfa()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"User 'test' has MFA and can access VMs with privileges in subscription {AZURE_SUBSCRIPTION}"
                )
                assert result[0].subscription == AZURE_SUBSCRIPTION
                assert result[0].resource_name == f"test@{DOMAIN}"
                assert result[0].resource_id == role_assigment_id

    def test_iam_role_assignment_priviledge_access_vm_has_mfa_no_mfa(self):
        iam_client = mock.MagicMock
        role_assigment_id = str(uuid4())
        entra_client = mock.MagicMock
        user_id = str(uuid4())

        with mock.patch(
            "prowler.providers.azure.services.iam.iam_role_assignment_priviledge_access_vm_has_mfa.iam_role_assignment_priviledge_access_vm_has_mfa.iam_client",
            new=iam_client,
        ):
            with mock.patch(
                "prowler.providers.azure.services.iam.iam_role_assignment_priviledge_access_vm_has_mfa.iam_role_assignment_priviledge_access_vm_has_mfa.entra_client",
                new=entra_client,
            ):
                from prowler.providers.azure.services.iam.iam_role_assignment_priviledge_access_vm_has_mfa.iam_role_assignment_priviledge_access_vm_has_mfa import (
                    iam_role_assignment_priviledge_access_vm_has_mfa,
                )

                iam_client.role_assignments = {
                    AZURE_SUBSCRIPTION: {
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

                check = iam_role_assignment_priviledge_access_vm_has_mfa()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"User 'test' has no MFA and can access VMs with privileges in subscription {AZURE_SUBSCRIPTION}"
                )
                assert result[0].subscription == AZURE_SUBSCRIPTION
                assert result[0].resource_name == f"test@{DOMAIN}"
                assert result[0].resource_id == role_assigment_id

    def test_iam_role_assignment_priviledge_access_vm_has_mfa_no_user(self):
        iam_client = mock.MagicMock
        role_assigment_id = str(uuid4())
        entra_client = mock.MagicMock
        user_id = str(uuid4())

        with mock.patch(
            "prowler.providers.azure.services.iam.iam_role_assignment_priviledge_access_vm_has_mfa.iam_role_assignment_priviledge_access_vm_has_mfa.iam_client",
            new=iam_client,
        ):
            with mock.patch(
                "prowler.providers.azure.services.iam.iam_role_assignment_priviledge_access_vm_has_mfa.iam_role_assignment_priviledge_access_vm_has_mfa.entra_client",
                new=entra_client,
            ):
                from prowler.providers.azure.services.iam.iam_role_assignment_priviledge_access_vm_has_mfa.iam_role_assignment_priviledge_access_vm_has_mfa import (
                    iam_role_assignment_priviledge_access_vm_has_mfa,
                )

                iam_client.role_assignments = {
                    AZURE_SUBSCRIPTION: {
                        role_assigment_id: RoleAssignment(
                            role_id=VIRTUAL_MACHINE_ADMINISTRATOR_LOGIN_ROLE_ID,
                            agent_type="User",
                            agent_id=user_id,
                        )
                    }
                }

                entra_client.users = {DOMAIN: {}}

                check = iam_role_assignment_priviledge_access_vm_has_mfa()
                result = check.execute()
                assert len(result) == 0

    def test_iam_role_assignment_priviledge_access_vm_has_mfa_no_role(self):
        iam_client = mock.MagicMock
        role_assigment_id = str(uuid4())
        entra_client = mock.MagicMock
        user_id = str(uuid4())

        with mock.patch(
            "prowler.providers.azure.services.iam.iam_role_assignment_priviledge_access_vm_has_mfa.iam_role_assignment_priviledge_access_vm_has_mfa.iam_client",
            new=iam_client,
        ):
            with mock.patch(
                "prowler.providers.azure.services.iam.iam_role_assignment_priviledge_access_vm_has_mfa.iam_role_assignment_priviledge_access_vm_has_mfa.entra_client",
                new=entra_client,
            ):
                from prowler.providers.azure.services.iam.iam_role_assignment_priviledge_access_vm_has_mfa.iam_role_assignment_priviledge_access_vm_has_mfa import (
                    iam_role_assignment_priviledge_access_vm_has_mfa,
                )

                iam_client.role_assignments = {
                    AZURE_SUBSCRIPTION: {
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

                check = iam_role_assignment_priviledge_access_vm_has_mfa()
                result = check.execute()
                assert len(result) == 0
