from datetime import datetime
from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class Test_iam_sa_dormant_user_managed_keys:
    def test_iam_no_sa(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.iam.iam_sa_dormant_user_managed_keys.iam_sa_dormant_user_managed_keys.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.gcp.services.iam.iam_sa_dormant_user_managed_keys.iam_sa_dormant_user_managed_keys import (
                iam_sa_dormant_user_managed_keys,
            )

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION
            iam_client.service_accounts = []

            check = iam_sa_dormant_user_managed_keys()
            result = check.execute()
            assert len(result) == 0

    def test_iam_sa_dormant_no_keys(self):
        iam_client = mock.MagicMock()
        monitoring_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.iam.iam_sa_dormant_user_managed_keys.iam_sa_dormant_user_managed_keys.iam_client",
                new=iam_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.iam.iam_sa_dormant_user_managed_keys.iam_sa_dormant_user_managed_keys.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.iam.iam_sa_dormant_user_managed_keys.iam_sa_dormant_user_managed_keys import (
                iam_sa_dormant_user_managed_keys,
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
                    uniqueId="111222233334444",
                )
            ]

            monitoring_client.sa_keys_metrics = set(
                ["90c48f61c65cd56224a12ab18e6ee9ca9c3aee7c"]
            )

            check = iam_sa_dormant_user_managed_keys()
            result = check.execute()
            assert len(result) == 0

    def test_iam_sa_dormant_system_managed_keys(self):
        iam_client = mock.MagicMock()
        monitoring_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.iam.iam_sa_dormant_user_managed_keys.iam_sa_dormant_user_managed_keys.iam_client",
                new=iam_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.iam.iam_sa_dormant_user_managed_keys.iam_sa_dormant_user_managed_keys.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.iam.iam_sa_dormant_user_managed_keys.iam_sa_dormant_user_managed_keys import (
                iam_sa_dormant_user_managed_keys,
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
                            name="90c48f61c65cd56224a12ab18e6ee9ca9c3aee7c",
                            origin="GOOGLE_PROVIDED",
                            type="SYSTEM_MANAGED",
                            valid_after=datetime.strptime("2024-07-10", "%Y-%m-%d"),
                            valid_before=datetime.strptime("9999-12-31", "%Y-%m-%d"),
                        )
                    ],
                    project_id=GCP_PROJECT_ID,
                    uniqueId="111222233334444",
                )
            ]

            monitoring_client.sa_keys_metrics = set(
                ["90c48f61c65cd56224a12ab18e6ee9ca9c3aee7c"]
            )

            check = iam_sa_dormant_user_managed_keys()
            result = check.execute()
            assert len(result) == 0

    def test_iam_sa_dormant_user_managed_keys(self):
        iam_client = mock.MagicMock()
        monitoring_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.iam.iam_sa_dormant_user_managed_keys.iam_sa_dormant_user_managed_keys.iam_client",
                new=iam_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.iam.iam_sa_dormant_user_managed_keys.iam_sa_dormant_user_managed_keys.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.iam.iam_sa_dormant_user_managed_keys.iam_sa_dormant_user_managed_keys import (
                iam_sa_dormant_user_managed_keys,
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
                            name="90c48f61c65cd56224a12ab18e6ee9ca9c3aee7c",
                            origin="GOOGLE_PROVIDED",
                            type="USER_MANAGED",
                            valid_after=datetime.strptime("2024-07-10", "%Y-%m-%d"),
                            valid_before=datetime.strptime("9999-12-31", "%Y-%m-%d"),
                        )
                    ],
                    project_id=GCP_PROJECT_ID,
                    uniqueId="111222233334444",
                )
            ]

            monitoring_client.sa_keys_metrics = set(
                ["90c48f61c65cd56224a12ab18e6ee9ca9c3aee7c"]
            )

            check = iam_sa_dormant_user_managed_keys()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"User-managed key {iam_client.service_accounts[0].keys[0].name} for account {iam_client.service_accounts[0].email} was used over the last 180 days."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].keys[0].name
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].email

    def test_iam_sa_dormant_mixed_keys(self):
        iam_client = mock.MagicMock()
        monitoring_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.iam.iam_sa_dormant_user_managed_keys.iam_sa_dormant_user_managed_keys.iam_client",
                new=iam_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.iam.iam_sa_dormant_user_managed_keys.iam_sa_dormant_user_managed_keys.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.iam.iam_sa_dormant_user_managed_keys.iam_sa_dormant_user_managed_keys import (
                iam_sa_dormant_user_managed_keys,
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
                            name="90c48f61c65cd56224a12ab18e6ee9ca9c3aee7c",
                            origin="GOOGLE_PROVIDED",
                            type="SYSTEM_MANAGED",
                            valid_after=datetime.strptime("2024-07-10", "%Y-%m-%d"),
                            valid_before=datetime.strptime("9999-12-31", "%Y-%m-%d"),
                        ),
                        Key(
                            name="e5e3800831ac1adc8a5849da7d827b4724b1fce8",
                            origin="GOOGLE_PROVIDED",
                            type="USER_MANAGED",
                            valid_after=datetime.strptime("2024-07-10", "%Y-%m-%d"),
                            valid_before=datetime.strptime("9999-12-31", "%Y-%m-%d"),
                        ),
                        Key(
                            name="f8e4771561be5cda9b1267add7006c5143e3a220",
                            origin="GOOGLE_PROVIDED",
                            type="USER_MANAGED",
                            valid_after=datetime.strptime("2024-07-10", "%Y-%m-%d"),
                            valid_before=datetime.strptime("9999-12-31", "%Y-%m-%d"),
                        ),
                    ],
                    project_id=GCP_PROJECT_ID,
                    uniqueId="111222233334444",
                )
            ]

            monitoring_client.sa_keys_metrics = set(
                ["f8e4771561be5cda9b1267add7006c5143e3a220"]
            )

            check = iam_sa_dormant_user_managed_keys()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"User-managed key {iam_client.service_accounts[0].keys[1].name} for account {iam_client.service_accounts[0].email} was not used over the last 180 days. Consider deleting it."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].keys[1].name
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == iam_client.service_accounts[0].email

            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == f"User-managed key {iam_client.service_accounts[0].keys[2].name} for account {iam_client.service_accounts[0].email} was used over the last 180 days."
            )
            assert result[1].resource_id == iam_client.service_accounts[0].keys[2].name
            assert result[1].project_id == GCP_PROJECT_ID
            assert result[1].location == GCP_US_CENTER1_LOCATION
            assert result[1].resource_name == iam_client.service_accounts[0].email
