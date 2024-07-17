import re
from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class TestCloudStorageBucketUniformBucketLevelAccess:
    def test_bucket_with_uniform_bucket_level_access_enabled(self):
        cloudstorage_client = mock.MagicMock()

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uniform_bucket_level_access.cloudstorage_bucket_uniform_bucket_level_access.cloudstorage_client",
            new=cloudstorage_client,
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uniform_bucket_level_access.cloudstorage_bucket_uniform_bucket_level_access import (
                cloudstorage_bucket_uniform_bucket_level_access,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = "global"

            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.buckets = [
                Bucket(
                    name="bucket1",
                    id="bucket1",
                    region="US",
                    uniform_bucket_level_access=True,
                    public=False,
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = cloudstorage_bucket_uniform_bucket_level_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert re.search(
                "Bucket .* has uniform Bucket Level Access enabled.",
                result[0].status_extended,
            )
            assert result[0].resource_id == "bucket1"
            assert result[0].resource_name == "bucket1"
            assert result[0].location == "US"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_with_uniform_bucket_level_access_disabled(self):
        cloudstorage_client = mock.MagicMock()

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uniform_bucket_level_access.cloudstorage_bucket_uniform_bucket_level_access.cloudstorage_client",
            new=cloudstorage_client,
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uniform_bucket_level_access.cloudstorage_bucket_uniform_bucket_level_access import (
                cloudstorage_bucket_uniform_bucket_level_access,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = "global"

            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.buckets = [
                Bucket(
                    name="bucket2",
                    id="bucket2",
                    region="US",
                    uniform_bucket_level_access=False,
                    public=False,
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = cloudstorage_bucket_uniform_bucket_level_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert re.search(
                "Bucket bucket2 has uniform Bucket Level Access disabled.",
                result[0].status_extended,
            )
            assert result[0].resource_id == "bucket2"
            assert result[0].resource_name == "bucket2"
            assert result[0].location == "US"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_no_buckets(self):
        cloudstorage_client = mock.MagicMock()

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uniform_bucket_level_access.cloudstorage_bucket_uniform_bucket_level_access.cloudstorage_client",
            new=cloudstorage_client,
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uniform_bucket_level_access.cloudstorage_bucket_uniform_bucket_level_access import (
                cloudstorage_bucket_uniform_bucket_level_access,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = "global"
            cloudstorage_client.buckets = []

            check = cloudstorage_bucket_uniform_bucket_level_access()
            result = check.execute()

            assert len(result) == 0
