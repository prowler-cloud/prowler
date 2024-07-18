import re
from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class Test_iam_sa_no_administrative_privileges:
    def test_iam_no_bindings(self):
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

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            from prowler.providers.gcp.services.iam.iam_service import ServiceAccount

            iam_client.service_accounts = [
                ServiceAccount(
                    name="service1",
                    email="service1",
                    display_name="service1",
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
            for idx, r in enumerate(result):
                assert r.status == "PASS"
                assert re.search(
                    "Account .* has no administrative privileges.",
                    r.status_extended,
                )
                assert r.resource_id == iam_client.service_accounts[0].email
                assert r.project_id == GCP_PROJECT_ID
                assert r.location == iam_client.region
                assert r.resource_name == iam_client.service_accounts[0].name

    def test_iam_viewer_role_binding(self):
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

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            from prowler.providers.gcp.services.iam.iam_service import ServiceAccount

            iam_client.service_accounts = [
                ServiceAccount(
                    name="service1",
                    email="service1",
                    display_name="service1",
                    keys=[],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Binding,
            )

            cloudresourcemanager_client.bindings = [
                Binding(
                    role="roles/viewer",
                    members=["serviceAccount:service1"],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 1
            for idx, r in enumerate(result):
                assert r.status == "PASS"
                assert re.search(
                    "Account .* has no administrative privileges.",
                    r.status_extended,
                )
                assert r.resource_id == iam_client.service_accounts[0].email
                assert r.project_id == GCP_PROJECT_ID
                assert r.location == iam_client.region
                assert r.resource_name == iam_client.service_accounts[0].name

    def test_iam_admin_role_binding(self):
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

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            from prowler.providers.gcp.services.iam.iam_service import ServiceAccount

            iam_client.service_accounts = [
                ServiceAccount(
                    name="service1",
                    email="service1",
                    display_name="service1",
                    keys=[],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Binding,
            )

            cloudresourcemanager_client.bindings = [
                Binding(
                    role="roles/admin",
                    members=["serviceAccount:service1"],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 1
            for idx, r in enumerate(result):
                assert r.status == "FAIL"
                assert re.search(
                    "Account .* has administrative privileges with .*",
                    r.status_extended,
                )
                assert r.resource_id == iam_client.service_accounts[0].email
                assert r.project_id == GCP_PROJECT_ID
                assert r.location == iam_client.region
                assert r.resource_name == iam_client.service_accounts[0].name

    def test_iam_owner_role_binding(self):
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

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            from prowler.providers.gcp.services.iam.iam_service import ServiceAccount

            iam_client.service_accounts = [
                ServiceAccount(
                    name="service1",
                    email="service1",
                    display_name="service1",
                    keys=[],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Binding,
            )

            cloudresourcemanager_client.bindings = [
                Binding(
                    role="roles/owner",
                    members=["serviceAccount:service1"],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 1
            for idx, r in enumerate(result):
                assert r.status == "FAIL"
                assert re.search(
                    "Account .* has administrative privileges with .*",
                    r.status_extended,
                )
                assert r.resource_id == iam_client.service_accounts[0].email
                assert r.project_id == GCP_PROJECT_ID
                assert r.location == iam_client.region
                assert r.resource_name == iam_client.service_accounts[0].name

    def test_iam_editor_role_binding(self):
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

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            from prowler.providers.gcp.services.iam.iam_service import ServiceAccount

            iam_client.service_accounts = [
                ServiceAccount(
                    name="service1",
                    email="service1",
                    display_name="service1",
                    keys=[],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Binding,
            )

            cloudresourcemanager_client.bindings = [
                Binding(
                    role="roles/editor",
                    members=["serviceAccount:service1"],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 1
            for idx, r in enumerate(result):
                assert r.status == "FAIL"
                assert re.search(
                    "Account .* has administrative privileges with .*",
                    r.status_extended,
                )
                assert r.resource_id == iam_client.service_accounts[0].email
                assert r.project_id == GCP_PROJECT_ID
                assert r.location == iam_client.region
                assert r.resource_name == iam_client.service_accounts[0].name

    def test_iam_role_binding_different_email(self):
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

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            from prowler.providers.gcp.services.iam.iam_service import ServiceAccount

            iam_client.service_accounts = [
                ServiceAccount(
                    name="service1",
                    email="service1",
                    display_name="service1",
                    keys=[],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Binding,
            )

            cloudresourcemanager_client.bindings = [
                Binding(
                    role="roles/admin",
                    members=["serviceAccount:service2"],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 1
            for idx, r in enumerate(result):
                assert r.status == "PASS"
                assert re.search(
                    "Account .* has no administrative privileges.",
                    r.status_extended,
                )
                assert r.resource_id == iam_client.service_accounts[0].email
                assert r.project_id == GCP_PROJECT_ID
                assert r.location == iam_client.region
                assert r.resource_name == iam_client.service_accounts[0].name
