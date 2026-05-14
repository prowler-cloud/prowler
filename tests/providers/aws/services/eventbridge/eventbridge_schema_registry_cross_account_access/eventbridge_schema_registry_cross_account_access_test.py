from unittest import mock
from uuid import uuid4

from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

test_schema_name = str(uuid4())
test_schema_arn = f"arn:aws:schemas:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{test_schema_name}"
self_account_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowReadWrite",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"},
            "Action": "schemas:*",
            "Resource": f"arn:aws:schemas:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{test_schema_name}",
        }
    ],
}

self_other_account_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowReadWrite",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
            "Action": "schemas:*",
            "Resource": f"arn:aws:schemas:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{test_schema_name}",
        }
    ],
}

self_asterisk_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowReadWrite",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "schemas:*",
            "Resource": f"arn:aws:schemas:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{test_schema_name}",
        }
    ],
}


class Test_eventbridge_schema_registry_cross_account_access:
    def test_no_schemas(self):
        schema_client = mock.MagicMock
        schema_client.registries = {}
        schema_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.aws.services.eventbridge.eventbridge_service.Schema",
                new=schema_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.eventbridge.schema_client.schema_client",
                new=schema_client,
            ),
        ):
            from prowler.providers.aws.services.eventbridge.eventbridge_schema_registry_cross_account_access.eventbridge_schema_registry_cross_account_access import (
                eventbridge_schema_registry_cross_account_access,
            )

            check = eventbridge_schema_registry_cross_account_access()
            result = check.execute()
            assert len(result) == 0

    def test_schemas_self_account(self):
        from prowler.providers.aws.services.eventbridge.eventbridge_service import (
            Registry,
        )

        schema_client = mock.MagicMock
        schema_client.audited_account = AWS_ACCOUNT_NUMBER
        schema_client.audit_config = {}
        schema_client.registries = {
            test_schema_arn: Registry(
                name=test_schema_name,
                arn=test_schema_arn,
                region=AWS_REGION_EU_WEST_1,
                tags=[],
                policy=self_account_policy,
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.eventbridge.eventbridge_service.Schema",
                new=schema_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.eventbridge.schema_client.schema_client",
                new=schema_client,
            ),
        ):
            from prowler.providers.aws.services.eventbridge.eventbridge_schema_registry_cross_account_access.eventbridge_schema_registry_cross_account_access import (
                eventbridge_schema_registry_cross_account_access,
            )

            check = eventbridge_schema_registry_cross_account_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"EventBridge schema registry {test_schema_name} does not allow cross-account access."
            )
            assert result[0].resource_id == test_schema_name
            assert result[0].resource_arn == test_schema_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_schemas_other_account(self):
        from prowler.providers.aws.services.eventbridge.eventbridge_service import (
            Registry,
        )

        schema_client = mock.MagicMock
        schema_client.audited_account = AWS_ACCOUNT_NUMBER
        schema_client.audit_config = {}
        schema_client.registries = {
            test_schema_arn: Registry(
                name=test_schema_name,
                arn=test_schema_arn,
                region=AWS_REGION_EU_WEST_1,
                tags=[],
                policy=self_other_account_policy,
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.eventbridge.eventbridge_service.Schema",
                new=schema_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.eventbridge.schema_client.schema_client",
                new=schema_client,
            ),
        ):
            from prowler.providers.aws.services.eventbridge.eventbridge_schema_registry_cross_account_access.eventbridge_schema_registry_cross_account_access import (
                eventbridge_schema_registry_cross_account_access,
            )

            check = eventbridge_schema_registry_cross_account_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"EventBridge schema registry {test_schema_name} allows cross-account access."
            )
            assert result[0].resource_id == test_schema_name
            assert result[0].resource_arn == test_schema_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_schemas_asterisk_principal(self):
        from prowler.providers.aws.services.eventbridge.eventbridge_service import (
            Registry,
        )

        schema_client = mock.MagicMock
        schema_client.audited_account = AWS_ACCOUNT_NUMBER
        schema_client.audit_config = {}
        schema_client.registries = {
            test_schema_arn: Registry(
                name=test_schema_name,
                arn=test_schema_arn,
                region=AWS_REGION_EU_WEST_1,
                tags=[],
                policy=self_asterisk_policy,
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.eventbridge.eventbridge_service.Schema",
                new=schema_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.eventbridge.schema_client.schema_client",
                new=schema_client,
            ),
        ):
            from prowler.providers.aws.services.eventbridge.eventbridge_schema_registry_cross_account_access.eventbridge_schema_registry_cross_account_access import (
                eventbridge_schema_registry_cross_account_access,
            )

            check = eventbridge_schema_registry_cross_account_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"EventBridge schema registry {test_schema_name} allows cross-account access."
            )
            assert result[0].resource_id == test_schema_name
            assert result[0].resource_arn == test_schema_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
