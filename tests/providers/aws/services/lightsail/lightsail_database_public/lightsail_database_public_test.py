from unittest.mock import MagicMock, patch

from prowler.providers.aws.services.lightsail.lightsail_service import Database
from tests.providers.aws.utils import (
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_EAST_1_AZA,
    BASE_LIGHTSAIL_ARN,
    set_mocked_aws_provider,
)


class Test_lightsail_database_public:
    def test_lightsail_no_databases(self):
        lightsail_client = MagicMock
        lightsail_client.databases = {}

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), patch(
            "prowler.providers.aws.services.lightsail.lightsail_service.Lightsail",
            new=lightsail_client,
        ):
            from prowler.providers.aws.services.lightsail.lightsail_database_public.lightsail_database_public import (
                lightsail_database_public,
            )

            check = lightsail_database_public()
            result = check.execute()

            assert len(result) == 0

    def test_lightsail_database_public(self):
        lightsail_client = MagicMock
        lightsail_client.databases = {
            f"{BASE_LIGHTSAIL_ARN}:Database/test-database": Database(
                name="test-database",
                id="1234/5678",
                tags=[],
                region=AWS_REGION_US_EAST_1,
                availability_zone=AWS_REGION_US_EAST_1_AZA,
                engine="mysql",
                engine_version="5.7",
                size="nano",
                status="running",
                master_username="admin",
                public_access=True,
            )
        }

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), patch(
            "prowler.providers.aws.services.lightsail.lightsail_service.Lightsail",
            new=lightsail_client,
        ):
            from prowler.providers.aws.services.lightsail.lightsail_database_public.lightsail_database_public import (
                lightsail_database_public,
            )

            check = lightsail_database_public()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "Database 'test-database' is public."
            assert result[0].resource_id == "1234/5678"
            assert (
                result[0].resource_arn == f"{BASE_LIGHTSAIL_ARN}:Database/test-database"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_lightsail_database_private(self):
        lightsail_client = MagicMock
        lightsail_client.databases = {
            f"{BASE_LIGHTSAIL_ARN}:Database/test-database": Database(
                name="test-database",
                id="1234/5678",
                tags=[],
                region=AWS_REGION_US_EAST_1,
                availability_zone=AWS_REGION_US_EAST_1_AZA,
                engine="mysql",
                engine_version="5.7",
                size="nano",
                status="running",
                master_username="admin",
                public_access=False,
            )
        }

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), patch(
            "prowler.providers.aws.services.lightsail.lightsail_service.Lightsail",
            new=lightsail_client,
        ):
            from prowler.providers.aws.services.lightsail.lightsail_database_public.lightsail_database_public import (
                lightsail_database_public,
            )

            check = lightsail_database_public()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended == "Database 'test-database' is not public."
            )
            assert result[0].resource_id == "1234/5678"
            assert (
                result[0].resource_arn == f"{BASE_LIGHTSAIL_ARN}:Database/test-database"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1
