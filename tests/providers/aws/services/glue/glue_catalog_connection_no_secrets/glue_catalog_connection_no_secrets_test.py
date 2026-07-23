from unittest import mock

import botocore
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call_no_connections(self, operation_name, kwarg):
    if operation_name == "GetConnections":
        return {"ConnectionList": []}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_no_secrets(self, operation_name, kwarg):
    if operation_name == "GetConnections":
        return {
            "ConnectionList": [
                {
                    "Name": "jdbc-clean",
                    "ConnectionType": "JDBC",
                    "ConnectionProperties": {
                        "JDBC_CONNECTION_URL": "jdbc:postgresql://db.example:5432/app",
                        "USERNAME": "app_user",
                    },
                }
            ]
        }
    if operation_name == "GetTags":
        return {"Tags": {"env": "test"}}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_with_secrets(self, operation_name, kwarg):
    if operation_name == "GetConnections":
        return {
            "ConnectionList": [
                {
                    "Name": "jdbc-secret",
                    "ConnectionType": "JDBC",
                    "ConnectionProperties": {
                        "JDBC_CONNECTION_URL": "jdbc:postgresql://db.example:5432/app",
                        "PASSWORD": "AKIAsupersecretkey1234",
                    },
                }
            ]
        }
    if operation_name == "GetTags":
        return {"Tags": {"env": "test"}}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_empty_properties(self, operation_name, kwarg):
    if operation_name == "GetConnections":
        return {
            "ConnectionList": [
                {
                    "Name": "empty-props",
                    "ConnectionType": "JDBC",
                    "ConnectionProperties": {},
                }
            ]
        }
    if operation_name == "GetTags":
        return {"Tags": {}}
    return make_api_call(self, operation_name, kwarg)


class Test_glue_catalog_connection_no_secrets:
    @mock_aws
    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_no_connections,
    )
    def test_glue_no_connections(self):
        from prowler.providers.aws.services.glue.glue_service import Glue

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.glue.glue_catalog_connection_no_secrets.glue_catalog_connection_no_secrets.glue_client",
                new=Glue(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.glue.glue_catalog_connection_no_secrets.glue_catalog_connection_no_secrets import (
                glue_catalog_connection_no_secrets,
            )

            check = glue_catalog_connection_no_secrets()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_no_secrets
    )
    def test_glue_connection_no_secrets(self):
        from prowler.providers.aws.services.glue.glue_service import Glue

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        connection_arn = (
            f"arn:aws:glue:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:"
            f"connection/jdbc-clean"
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.glue.glue_catalog_connection_no_secrets.glue_catalog_connection_no_secrets.glue_client",
                new=Glue(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.glue.glue_catalog_connection_no_secrets.glue_catalog_connection_no_secrets import (
                glue_catalog_connection_no_secrets,
            )

            check = glue_catalog_connection_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No secrets found in Glue connection jdbc-clean."
            )
            assert result[0].resource_id == "jdbc-clean"
            assert result[0].resource_arn == connection_arn
            assert result[0].resource_tags == [{"env": "test"}]
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_with_secrets
    )
    def test_glue_connection_with_secrets(self):
        from prowler.providers.aws.services.glue.glue_service import Glue

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        connection_arn = (
            f"arn:aws:glue:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:"
            f"connection/jdbc-secret"
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.glue.glue_catalog_connection_no_secrets.glue_catalog_connection_no_secrets.glue_client",
                new=Glue(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.glue.glue_catalog_connection_no_secrets.glue_catalog_connection_no_secrets import (
                glue_catalog_connection_no_secrets,
            )

            check = glue_catalog_connection_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Potential secret found" in result[0].status_extended
            assert "jdbc-secret" in result[0].status_extended
            assert "AKIAsupersecretkey1234" not in result[0].status_extended
            assert result[0].resource_id == "jdbc-secret"
            assert result[0].resource_arn == connection_arn
            assert result[0].resource_tags == [{"env": "test"}]
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_empty_properties,
    )
    def test_glue_connection_empty_properties(self):
        from prowler.providers.aws.services.glue.glue_service import Glue

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        connection_arn = (
            f"arn:aws:glue:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:"
            f"connection/empty-props"
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.glue.glue_catalog_connection_no_secrets.glue_catalog_connection_no_secrets.glue_client",
                new=Glue(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.glue.glue_catalog_connection_no_secrets.glue_catalog_connection_no_secrets import (
                glue_catalog_connection_no_secrets,
            )

            check = glue_catalog_connection_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No secrets found in Glue connection empty-props."
            )
            assert result[0].resource_id == "empty-props"
            assert result[0].resource_arn == connection_arn
            assert result[0].resource_tags == [{}]
            assert result[0].region == AWS_REGION_US_EAST_1
