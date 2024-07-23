from datetime import datetime
from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class Test_iam_sa_user_managed_key_rotate_90_days:
    def test_iam_no_sa(self):
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_user_managed_key_rotate_90_days.iam_sa_user_managed_key_rotate_90_days.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.iam.iam_sa_user_managed_key_rotate_90_days.iam_sa_user_managed_key_rotate_90_days import (
                iam_sa_user_managed_key_rotate_90_days,
            )

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION
            iam_client.service_accounts = []

            check = iam_sa_user_managed_key_rotate_90_days()
            result = check.execute()
            assert len(result) == 0

    def test_iam_sa_no_keys(self):
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_user_managed_key_rotate_90_days.iam_sa_user_managed_key_rotate_90_days.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.iam.iam_sa_user_managed_key_rotate_90_days.iam_sa_user_managed_key_rotate_90_days import (
                iam_sa_user_managed_key_rotate_90_days,
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

            check = iam_sa_user_managed_key_rotate_90_days()
            result = check.execute()
            assert len(result) == 0

    def test_iam_sa_user_managed_key_rotate_90_days(self):
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_user_managed_key_rotate_90_days.iam_sa_user_managed_key_rotate_90_days.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.iam.iam_sa_user_managed_key_rotate_90_days.iam_sa_user_managed_key_rotate_90_days import (
                iam_sa_user_managed_key_rotate_90_days,
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
                            valid_after=datetime.now(),
                            valid_before=datetime.strptime("9999-12-31", "%Y-%m-%d"),
                        )
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_user_managed_key_rotate_90_days()
            last_rotated = (
                datetime.now() - iam_client.service_accounts[0].keys[0].valid_after
            ).days
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"User-managed key {iam_client.service_accounts[0].keys[0].name} for account {iam_client.service_accounts[0].email} was rotated over the last 90 days ({last_rotated} days ago)."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].keys[0].name
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].email

    def test_iam_sa_user_managed_key_no_rotate_90_days(self):
        iam_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_sa_user_managed_key_rotate_90_days.iam_sa_user_managed_key_rotate_90_days.iam_client",
            new=iam_client,
        ):
            from prowler.providers.gcp.services.iam.iam_sa_user_managed_key_rotate_90_days.iam_sa_user_managed_key_rotate_90_days import (
                iam_sa_user_managed_key_rotate_90_days,
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
                            valid_after=datetime.strptime("2023-07-10", "%Y-%m-%d"),
                            valid_before=datetime.strptime("9999-12-31", "%Y-%m-%d"),
                        )
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = iam_sa_user_managed_key_rotate_90_days()
            last_rotated = (
                datetime.now() - iam_client.service_accounts[0].keys[0].valid_after
            ).days
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"User-managed key {iam_client.service_accounts[0].keys[0].name} for account {iam_client.service_accounts[0].email} was not rotated over the last 90 days ({last_rotated} days ago)."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].keys[0].name
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].email
