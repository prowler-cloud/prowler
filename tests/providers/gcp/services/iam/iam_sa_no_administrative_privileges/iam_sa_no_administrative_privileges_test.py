from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class Test_iam_sa_no_administrative_privileges:
    def test_iam_no_sa(self):
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges import (
                iam_sa_no_administrative_privileges,
            )

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION
            iam_client.service_accounts = []

            check = iam_sa_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 0

    def test_iam_sa_no_bindings(self):
        cloudresourcemanager_client = mock.MagicMock
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges import (
                iam_sa_no_administrative_privileges,
            )
            from prowler.providers.gcp.services.iam.iam_service import ServiceAccount

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            iam_client.service_accounts = [
                ServiceAccount(
                    name="projects/my-project/serviceAccounts/my-service-account@my-project.iam.gserviceaccount.com",
                    email="my-service-account@my-project.iam.gserviceaccount.com",
                    display_name="My service account",
                    keys=[],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudresourcemanager_client.bindings = []
            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            check = iam_sa_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Account {iam_client.service_accounts[0].email} has no administrative privileges."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].email
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].name

    def test_iam_sa_binding_no_match_email(self):
        cloudresourcemanager_client = mock.MagicMock
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Binding,
            )
            from prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges import (
                iam_sa_no_administrative_privileges,
            )
            from prowler.providers.gcp.services.iam.iam_service import ServiceAccount

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            iam_client.service_accounts = [
                ServiceAccount(
                    name="projects/my-project/serviceAccounts/my-service-account@my-project.iam.gserviceaccount.com",
                    email="my-service-account@my-project.iam.gserviceaccount.com",
                    display_name="My service account",
                    keys=[],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            cloudresourcemanager_client.bindings = [
                Binding(
                    role="roles/admin",
                    members=[
                        "serviceAccount:not-my-service-account@my-project.iam.gserviceaccount.com"
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Account {iam_client.service_accounts[0].email} has no administrative privileges."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].email
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].name

    def test_iam_sa_viewer_role_binding(self):
        cloudresourcemanager_client = mock.MagicMock
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Binding,
            )
            from prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges import (
                iam_sa_no_administrative_privileges,
            )
            from prowler.providers.gcp.services.iam.iam_service import ServiceAccount

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            iam_client.service_accounts = [
                ServiceAccount(
                    name="projects/my-project/serviceAccounts/my-service-account@my-project.iam.gserviceaccount.com",
                    email="my-service-account@my-project.iam.gserviceaccount.com",
                    display_name="My service account",
                    keys=[],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            cloudresourcemanager_client.bindings = [
                Binding(
                    role="roles/viewer",
                    members=[
                        "serviceAccount:my-service-account@my-project.iam.gserviceaccount.com"
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Account {iam_client.service_accounts[0].email} has no administrative privileges."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].email
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].name

    def test_iam_sa_admin_role_binding(self):
        cloudresourcemanager_client = mock.MagicMock
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Binding,
            )
            from prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges import (
                iam_sa_no_administrative_privileges,
            )
            from prowler.providers.gcp.services.iam.iam_service import ServiceAccount

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            iam_client.service_accounts = [
                ServiceAccount(
                    name="projects/my-project/serviceAccounts/my-service-account@my-project.iam.gserviceaccount.com",
                    email="my-service-account@my-project.iam.gserviceaccount.com",
                    display_name="My service account",
                    keys=[],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            cloudresourcemanager_client.bindings = [
                Binding(
                    role="roles/admin",
                    members=[
                        "serviceAccount:my-service-account@my-project.iam.gserviceaccount.com"
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Account {iam_client.service_accounts[0].email} has administrative privileges with {cloudresourcemanager_client.bindings[0].role}."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].email
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].name

    def test_iam_sa_owner_role_binding(self):
        cloudresourcemanager_client = mock.MagicMock
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Binding,
            )
            from prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges import (
                iam_sa_no_administrative_privileges,
            )
            from prowler.providers.gcp.services.iam.iam_service import ServiceAccount

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            iam_client.service_accounts = [
                ServiceAccount(
                    name="projects/my-project/serviceAccounts/my-service-account@my-project.iam.gserviceaccount.com",
                    email="my-service-account@my-project.iam.gserviceaccount.com",
                    display_name="My service account",
                    keys=[],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            cloudresourcemanager_client.bindings = [
                Binding(
                    role="roles/owner",
                    members=[
                        "serviceAccount:my-service-account@my-project.iam.gserviceaccount.com"
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Account {iam_client.service_accounts[0].email} has administrative privileges with {cloudresourcemanager_client.bindings[0].role}."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].email
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].name

    def test_iam_sa_editor_role_binding(self):
        cloudresourcemanager_client = mock.MagicMock
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Binding,
            )
            from prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges import (
                iam_sa_no_administrative_privileges,
            )
            from prowler.providers.gcp.services.iam.iam_service import ServiceAccount

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            iam_client.service_accounts = [
                ServiceAccount(
                    name="projects/my-project/serviceAccounts/my-service-account@my-project.iam.gserviceaccount.com",
                    email="my-service-account@my-project.iam.gserviceaccount.com",
                    display_name="My service account",
                    keys=[],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            cloudresourcemanager_client.bindings = [
                Binding(
                    role="roles/editor",
                    members=[
                        "serviceAccount:my-service-account@my-project.iam.gserviceaccount.com"
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Account {iam_client.service_accounts[0].email} has administrative privileges with {cloudresourcemanager_client.bindings[0].role}."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].email
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].name

    def test_iam_sa_other_editor_role_binding(self):
        cloudresourcemanager_client = mock.MagicMock
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Binding,
            )
            from prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges import (
                iam_sa_no_administrative_privileges,
            )
            from prowler.providers.gcp.services.iam.iam_service import ServiceAccount

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            iam_client.service_accounts = [
                ServiceAccount(
                    name="projects/my-project/serviceAccounts/my-service-account@my-project.iam.gserviceaccount.com",
                    email="my-service-account@my-project.iam.gserviceaccount.com",
                    display_name="My service account",
                    keys=[],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            cloudresourcemanager_client.bindings = [
                Binding(
                    role="accessapproval.configEditor",
                    members=[
                        "serviceAccount:my-service-account@my-project.iam.gserviceaccount.com"
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Account {iam_client.service_accounts[0].email} has no administrative privileges."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].email
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].name

    def test_iam_sa_role_binding_different_email(self):
        cloudresourcemanager_client = mock.MagicMock
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Binding,
            )
            from prowler.providers.gcp.services.iam.iam_sa_no_administrative_privileges.iam_sa_no_administrative_privileges import (
                iam_sa_no_administrative_privileges,
            )
            from prowler.providers.gcp.services.iam.iam_service import ServiceAccount

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            iam_client.service_accounts = [
                ServiceAccount(
                    name="projects/my-project/serviceAccounts/my-service-account@my-project.iam.gserviceaccount.com",
                    email="my-service-account@my-project.iam.gserviceaccount.com",
                    display_name="My service account",
                    keys=[],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            cloudresourcemanager_client.bindings = [
                Binding(
                    role="roles/admin",
                    members=[
                        "serviceAccount:my-new-service-account@my-project.iam.gserviceaccount.com"
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Account {iam_client.service_accounts[0].email} has no administrative privileges."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].email
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].name
