from datetime import datetime
from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class Test_iam_service_account_unused:
    def test_iam_no_sa(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.iam.iam_service_account_unused.iam_service_account_unused.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.gcp.services.iam.iam_service_account_unused.iam_service_account_unused import (
                iam_service_account_unused,
            )

            iam_client.project_ids = [GCP_PROJECT_ID]
            iam_client.region = GCP_US_CENTER1_LOCATION
            iam_client.service_accounts = []

            check = iam_service_account_unused()
            result = check.execute()
            assert len(result) == 0

    def test_iam_service_account_unused_single(self):
        iam_client = mock.MagicMock()
        monitoring_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.iam.iam_service_account_unused.iam_service_account_unused.iam_client",
                new=iam_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.iam.iam_service_account_unused.iam_service_account_unused.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.iam.iam_service import (
                Key,
                ServiceAccount,
            )
            from prowler.providers.gcp.services.iam.iam_service_account_unused.iam_service_account_unused import (
                iam_service_account_unused,
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

            monitoring_client.sa_api_metrics = set(["111222233334444"])
            monitoring_client.audit_config = {"max_unused_account_days": 30}

            check = iam_service_account_unused()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Service Account {iam_client.service_accounts[0].email} was used over the last 30 days."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].email
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource == iam_client.service_accounts[0]

    def test_iam_service_account_unused_mix(self):
        iam_client = mock.MagicMock()
        monitoring_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.iam.iam_service_account_unused.iam_service_account_unused.iam_client",
                new=iam_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.iam.iam_service_account_unused.iam_service_account_unused.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.iam.iam_service import (
                Key,
                ServiceAccount,
            )
            from prowler.providers.gcp.services.iam.iam_service_account_unused.iam_service_account_unused import (
                iam_service_account_unused,
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
                ),
                ServiceAccount(
                    name="projects/my-project/serviceAccounts/my-service-account2@my-project.iam.gserviceaccount.com",
                    email="my-service-account2@my-project.iam.gserviceaccount.com",
                    display_name="My service account 2",
                    keys=[],
                    project_id=GCP_PROJECT_ID,
                    uniqueId="55566666777888999",
                ),
            ]

            monitoring_client.sa_api_metrics = set(["111222233334444"])
            monitoring_client.audit_config = {"max_unused_account_days": 30}

            check = iam_service_account_unused()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Service Account {iam_client.service_accounts[0].email} was used over the last 30 days."
            )
            assert result[0].resource_id == iam_client.service_accounts[0].email
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource == iam_client.service_accounts[0]

            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == f"Service Account {iam_client.service_accounts[1].email} was not used over the last 30 days."
            )
            assert result[1].resource_id == iam_client.service_accounts[1].email
            assert result[1].project_id == GCP_PROJECT_ID
            assert result[1].location == GCP_US_CENTER1_LOCATION
            assert result[1].resource == iam_client.service_accounts[1]
