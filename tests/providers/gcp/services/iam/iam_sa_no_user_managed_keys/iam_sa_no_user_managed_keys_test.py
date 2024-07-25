from datetime import datetime
from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class Test_iam_sa_no_user_managed_keys:
    def test_iam_no_sa(self):
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_user_managed_keys.iam_sa_no_user_managed_keys.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.iam.iam_sa_no_user_managed_keys.iam_sa_no_user_managed_keys import (
                iam_sa_no_user_managed_keys,
            )

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION
            iam_client.service_accounts = []

            check = iam_sa_no_user_managed_keys()
            result = check.execute()
            assert len(result) == 0

    def test_iam_sa_no_keys(self):
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_user_managed_keys.iam_sa_no_user_managed_keys.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.iam.iam_sa_no_user_managed_keys.iam_sa_no_user_managed_keys import (
                iam_sa_no_user_managed_keys,
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

            check = iam_sa_no_user_managed_keys()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Account {iam_client.service_accounts[0].email} does not have user-managed keys."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].email
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].name

    def test_iam_sa_no_user_managed_keys(self):
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_user_managed_keys.iam_sa_no_user_managed_keys.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.iam.iam_sa_no_user_managed_keys.iam_sa_no_user_managed_keys import (
                iam_sa_no_user_managed_keys,
            )
            from prowler.providers.gcp.services.iam.iam_service import (
                Key,
                ServiceAccount,
            )

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            iam_client.service_accounts = [
                ServiceAccount(
                    name="projects/my-project/serviceAccounts/my-service-account@my-project.iam.gserviceaccount.com",
                    email="my-service-account@my-project.iam.gserviceaccount.com",
                    display_name="My service account",
                    keys=[
                        Key(
                            name="projects/my-project/serviceAccounts/my-service-account@my-project.iam.gserviceaccount.com/keys/90c48f61c65cd56224a12ab18e6ee9ca9c3aee7c",
                            origin="GOOGLE_PROVIDED",
                            type="SYSTEM_MANAGED",
                            valid_after=datetime.strptime("2024-07-10", "%Y-%m-%d"),
                            valid_before=datetime.strptime("9999-12-31", "%Y-%m-%d"),
                        )
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_no_user_managed_keys()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Account {iam_client.service_accounts[0].email} does not have user-managed keys."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].email
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].name

    def test_iam_sa_user_managed_keys(self):
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_user_managed_keys.iam_sa_no_user_managed_keys.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.iam.iam_sa_no_user_managed_keys.iam_sa_no_user_managed_keys import (
                iam_sa_no_user_managed_keys,
            )
            from prowler.providers.gcp.services.iam.iam_service import (
                Key,
                ServiceAccount,
            )

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            iam_client.service_accounts = [
                ServiceAccount(
                    name="projects/my-project/serviceAccounts/my-service-account@my-project.iam.gserviceaccount.com",
                    email="my-service-account@my-project.iam.gserviceaccount.com",
                    display_name="My service account",
                    keys=[
                        Key(
                            name="projects/my-project/serviceAccounts/my-service-account@my-project.iam.gserviceaccount.com/keys/90c48f61c65cd56224a12ab18e6ee9ca9c3aee7c",
                            origin="GOOGLE_PROVIDED",
                            type="USER_MANAGED",
                            valid_after=datetime.strptime("2024-07-10", "%Y-%m-%d"),
                            valid_before=datetime.strptime("9999-12-31", "%Y-%m-%d"),
                        )
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_no_user_managed_keys()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Account {iam_client.service_accounts[0].email} has user-managed keys."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].email
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].name

    def test_iam_sa_mixed_keys(self):
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_no_user_managed_keys.iam_sa_no_user_managed_keys.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.iam.iam_sa_no_user_managed_keys.iam_sa_no_user_managed_keys import (
                iam_sa_no_user_managed_keys,
            )
            from prowler.providers.gcp.services.iam.iam_service import (
                Key,
                ServiceAccount,
            )

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION

            iam_client.service_accounts = [
                ServiceAccount(
                    name="projects/my-project/serviceAccounts/my-service-account@my-project.iam.gserviceaccount.com",
                    email="my-service-account@my-project.iam.gserviceaccount.com",
                    display_name="My service account",
                    keys=[
                        Key(
                            name="projects/my-project/serviceAccounts/my-service-account@my-project.iam.gserviceaccount.com/keys/90c48f61c65cd56224a12ab18e6ee9ca9c3aee7c",
                            origin="GOOGLE_PROVIDED",
                            type="SYSTEM_MANAGED",
                            valid_after=datetime.strptime("2024-07-10", "%Y-%m-%d"),
                            valid_before=datetime.strptime("9999-12-31", "%Y-%m-%d"),
                        ),
                        Key(
                            name="projects/my-project/serviceAccounts/my-service-account@my-project.iam.gserviceaccount.com/keys/e5e3800831ac1adc8a5849da7d827b4724b1fce8",
                            origin="GOOGLE_PROVIDED",
                            type="USER_MANAGED",
                            valid_after=datetime.strptime("2024-07-10", "%Y-%m-%d"),
                            valid_before=datetime.strptime("9999-12-31", "%Y-%m-%d"),
                        ),
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_no_user_managed_keys()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Account {iam_client.service_accounts[0].email} has user-managed keys."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].email
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].name
