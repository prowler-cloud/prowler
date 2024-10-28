from unittest import mock
from uuid import uuid4

from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

test_table_name = str(uuid4())
test_table_arn = f"arn:aws:dynamodb:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:table/{test_table_name}"

test_restricted_policy = {
    "Version": "2012-10-17",
    "Id": "Table1_Policy_UUID",
    "Statement": [
        {
            "Sid": "Table1_AnonymousAccess_GetItem",
            "Effect": "Allow",
            "Principal": {"AWS": {AWS_ACCOUNT_NUMBER}},
            "Action": "dynamodb:BatchGetItem",
            "Resource": test_table_arn,
        }
    ],
}

test_public_policy = {
    "Version": "2012-10-17",
    "Id": "Table1_Policy_UUID",
    "Statement": [
        {
            "Sid": "Table1_AnonymousAccess_GetItem",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "dynamodb:BatchGetItem",
            "Resource": test_table_arn,
        }
    ],
}

test_public_policy_with_condition_same_account_not_valid = {
    "Version": "2012-10-17",
    "Id": "Table1_Policy_UUID",
    "Statement": [
        {
            "Sid": "Table1_AnonymousAccess_GetItem",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "dynamodb:BatchGetItem",
            "Resource": test_table_arn,
            "Condition": {
                "DateGreaterThan": {"aws:CurrentTime": "2009-01-31T12:00Z"},
                "DateLessThan": {"aws:CurrentTime": "2009-01-31T15:00Z"},
            },
        }
    ],
}

test_public_policy_with_condition_same_account = {
    "Version": "2012-10-17",
    "Id": "Table1_Policy_UUID",
    "Statement": [
        {
            "Sid": "Table1_AnonymousAccess_GetItem",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "dynamodb:BatchGetItem",
            "Resource": test_table_arn,
            "Condition": {
                "StringEquals": {"aws:SourceAccount": f"{AWS_ACCOUNT_NUMBER}"}
            },
        }
    ],
}

test_public_policy_with_condition_diff_account = {
    "Version": "2012-10-17",
    "Id": "Table1_Policy_UUID",
    "Statement": [
        {
            "Sid": "Table1_AnonymousAccess_GetItem",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "dynamodb:BatchGetItem",
            "Resource": test_table_arn,
            "Condition": {"StringEquals": {"aws:SourceAccount": "111122223333"}},
        }
    ],
}

test_public_policy_with_invalid_condition_block = {
    "Version": "2012-10-17",
    "Id": "Table1_Policy_UUID",
    "Statement": [
        {
            "Sid": "Table1_AnonymousAccess_GetItem",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "dynamodb:BatchGetItem",
            "Resource": test_table_arn,
            "Condition": {"DateGreaterThan": {"aws:CurrentTime": "2009-01-31T12:00Z"}},
        }
    ],
}


class Test_dynamodb_table_cross_account_access:
    def test_no_tables(self):
        dynamodb_client = mock.MagicMock
        dynamodb_client.tables = {}
        with mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_service.DynamoDB",
            new=dynamodb_client,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_client.dynamodb_client",
            new=dynamodb_client,
        ):
            from prowler.providers.aws.services.dynamodb.dynamodb_table_cross_account_access.dynamodb_table_cross_account_access import (
                dynamodb_table_cross_account_access,
            )

            check = dynamodb_table_cross_account_access()
            result = check.execute()
            assert len(result) == 0

    def test_tables_no_policy(self):
        dynamodb_client = mock.MagicMock
        from prowler.providers.aws.services.dynamodb.dynamodb_service import Table

        dynamodb_client.audited_account = AWS_ACCOUNT_NUMBER
        dynamodb_client.audit_config = {}
        arn = test_table_arn
        dynamodb_client.tables = {
            arn: Table(
                arn=arn,
                name=test_table_name,
                region=AWS_REGION_EU_WEST_1,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_service.DynamoDB",
            new=dynamodb_client,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_client.dynamodb_client",
            new=dynamodb_client,
        ):
            from prowler.providers.aws.services.dynamodb.dynamodb_table_cross_account_access.dynamodb_table_cross_account_access import (
                dynamodb_table_cross_account_access,
            )

            check = dynamodb_table_cross_account_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"DynamoDB table {test_table_name} does not have a resource-based policy."
            )
            assert result[0].resource_id == test_table_name
            assert result[0].resource_arn == test_table_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_tables_not_public(self):
        dynamodb_client = mock.MagicMock
        from prowler.providers.aws.services.dynamodb.dynamodb_service import Table

        dynamodb_client.audited_account = AWS_ACCOUNT_NUMBER
        dynamodb_client.audit_config = {}
        arn = test_table_arn
        dynamodb_client.tables = {
            arn: Table(
                arn=arn,
                name=test_table_name,
                region=AWS_REGION_EU_WEST_1,
                policy=test_restricted_policy,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_service.DynamoDB",
            new=dynamodb_client,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_client.dynamodb_client",
            new=dynamodb_client,
        ):
            from prowler.providers.aws.services.dynamodb.dynamodb_table_cross_account_access.dynamodb_table_cross_account_access import (
                dynamodb_table_cross_account_access,
            )

            check = dynamodb_table_cross_account_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"DynamoDB table {test_table_name} has a resource-based policy but is not cross account."
            )
            assert result[0].resource_id == test_table_name
            assert result[0].resource_arn == test_table_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_tables_public(self):
        dynamodb_client = mock.MagicMock
        from prowler.providers.aws.services.dynamodb.dynamodb_service import Table

        dynamodb_client.audited_account = AWS_ACCOUNT_NUMBER
        dynamodb_client.audit_config = {}
        arn = test_table_arn
        dynamodb_client.tables = {
            arn: Table(
                arn=test_table_arn,
                name=test_table_name,
                region=AWS_REGION_EU_WEST_1,
                policy=test_public_policy,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_service.DynamoDB",
            new=dynamodb_client,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_client.dynamodb_client",
            new=dynamodb_client,
        ):
            from prowler.providers.aws.services.dynamodb.dynamodb_table_cross_account_access.dynamodb_table_cross_account_access import (
                dynamodb_table_cross_account_access,
            )

            check = dynamodb_table_cross_account_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"DynamoDB table {test_table_name} has a resource-based policy allowing cross account access."
            )
            assert result[0].resource_id == test_table_name
            assert result[0].resource_arn == test_table_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_tables_public_with_condition_not_valid(self):
        dynamodb_client = mock.MagicMock
        from prowler.providers.aws.services.dynamodb.dynamodb_service import Table

        dynamodb_client.audited_account = AWS_ACCOUNT_NUMBER
        dynamodb_client.audit_config = {}
        arn = test_table_arn
        dynamodb_client.tables = {
            arn: Table(
                arn=test_table_arn,
                name=test_table_name,
                region=AWS_REGION_EU_WEST_1,
                policy=test_public_policy_with_condition_same_account_not_valid,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_service.DynamoDB",
            new=dynamodb_client,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_client.dynamodb_client",
            new=dynamodb_client,
        ):
            from prowler.providers.aws.services.dynamodb.dynamodb_table_cross_account_access.dynamodb_table_cross_account_access import (
                dynamodb_table_cross_account_access,
            )

            check = dynamodb_table_cross_account_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"DynamoDB table {test_table_name} has a resource-based policy allowing cross account access."
            )
            assert result[0].resource_id == test_table_name
            assert result[0].resource_arn == test_table_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_tables_public_with_condition_valid(self):
        dynamodb_client = mock.MagicMock
        from prowler.providers.aws.services.dynamodb.dynamodb_service import Table

        dynamodb_client.audited_account = AWS_ACCOUNT_NUMBER
        dynamodb_client.audit_config = {}
        arn = test_table_arn
        dynamodb_client.tables = {
            arn: Table(
                arn=test_table_arn,
                name=test_table_name,
                region=AWS_REGION_EU_WEST_1,
                policy=test_public_policy_with_condition_same_account,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_service.DynamoDB",
            new=dynamodb_client,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_client.dynamodb_client",
            new=dynamodb_client,
        ):
            from prowler.providers.aws.services.dynamodb.dynamodb_table_cross_account_access.dynamodb_table_cross_account_access import (
                dynamodb_table_cross_account_access,
            )

            check = dynamodb_table_cross_account_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"DynamoDB table {test_table_name} has a resource-based policy but is not cross account."
            )
            assert result[0].resource_id == test_table_name
            assert result[0].resource_arn == test_table_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_tables_public_with_condition_valid_with_other_account(self):
        dynamodb_client = mock.MagicMock
        from prowler.providers.aws.services.dynamodb.dynamodb_service import Table

        dynamodb_client.audited_account = AWS_ACCOUNT_NUMBER
        dynamodb_client.audit_config = {}
        arn = test_table_arn
        dynamodb_client.tables = {
            arn: Table(
                arn=test_table_arn,
                name=test_table_name,
                region=AWS_REGION_EU_WEST_1,
                policy=test_public_policy_with_condition_diff_account,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_service.DynamoDB",
            new=dynamodb_client,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_client.dynamodb_client",
            new=dynamodb_client,
        ):
            from prowler.providers.aws.services.dynamodb.dynamodb_table_cross_account_access.dynamodb_table_cross_account_access import (
                dynamodb_table_cross_account_access,
            )

            check = dynamodb_table_cross_account_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"DynamoDB table {test_table_name} has a resource-based policy allowing cross account access."
            )
            assert result[0].resource_id == test_table_name
            assert result[0].resource_arn == test_table_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_tables_public_with_condition_with_invalid_block(self):
        dynamodb_client = mock.MagicMock
        from prowler.providers.aws.services.dynamodb.dynamodb_service import Table

        dynamodb_client.audited_account = AWS_ACCOUNT_NUMBER
        dynamodb_client.audit_config = {}
        arn = test_table_arn
        dynamodb_client.tables = {
            arn: Table(
                arn=test_table_arn,
                name=test_table_name,
                region=AWS_REGION_EU_WEST_1,
                policy=test_public_policy_with_invalid_condition_block,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_service.DynamoDB",
            new=dynamodb_client,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_client.dynamodb_client",
            new=dynamodb_client,
        ):
            from prowler.providers.aws.services.dynamodb.dynamodb_table_cross_account_access.dynamodb_table_cross_account_access import (
                dynamodb_table_cross_account_access,
            )

            check = dynamodb_table_cross_account_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"DynamoDB table {test_table_name} has a resource-based policy allowing cross account access."
            )
            assert result[0].resource_id == test_table_name
            assert result[0].resource_arn == test_table_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
