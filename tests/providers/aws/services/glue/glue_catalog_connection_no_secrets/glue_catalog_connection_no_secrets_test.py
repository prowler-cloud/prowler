from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_glue_catalog_connection_no_secrets:
    @mock_aws
    def test_glue_no_connections(self):
        from prowler.providers.aws.services.glue.glue_service import Glue

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.glue.glue_catalog_connection_no_secrets.glue_catalog_connection_no_secrets.glue_client",
                new=Glue(aws_provider),
            ):
                from prowler.providers.aws.services.glue.glue_catalog_connection_no_secrets.glue_catalog_connection_no_secrets import (
                    glue_catalog_connection_no_secrets,
                )

                check = glue_catalog_connection_no_secrets()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_glue_connection_no_secrets(self):
        glue_client = client("glue", region_name=AWS_REGION_US_EAST_1)
        connection_name = "test-connection"

        glue_client.create_connection(
            ConnectionInput={
                "Name": connection_name,
                "ConnectionType": "JDBC",
                "ConnectionProperties": {
                    "JDBC_CONNECTION_URL": "jdbc:mysql://db.example.com:3306/test",
                    "JDBC_ENFORCE_SSL": "true",
                },
            }
        )

        from prowler.providers.aws.services.glue.glue_service import Glue

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.glue.glue_catalog_connection_no_secrets.glue_catalog_connection_no_secrets.glue_client",
                new=Glue(aws_provider),
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
                    == f"No secrets found in Glue Data Catalog connection {connection_name} properties."
                )
                assert result[0].resource_id == connection_name

    @mock_aws
    def test_glue_connection_with_secrets(self):
        glue_client = client("glue", region_name=AWS_REGION_US_EAST_1)
        connection_name = "test-connection"

        glue_client.create_connection(
            ConnectionInput={
                "Name": connection_name,
                "ConnectionType": "JDBC",
                "ConnectionProperties": {
                    "JDBC_CONNECTION_URL": "jdbc:mysql://db.example.com:3306/test",
                    # A syntactically valid JSON Web Token that Kingfisher flags
                    # as a secret (a bare high-entropy string is treated as a
                    # placeholder and ignored by the offline scanner).
                    "PASSWORD": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                },
            }
        )

        from prowler.providers.aws.services.glue.glue_service import Glue

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.glue.glue_catalog_connection_no_secrets.glue_catalog_connection_no_secrets.glue_client",
                new=Glue(aws_provider),
            ):
                from prowler.providers.aws.services.glue.glue_catalog_connection_no_secrets.glue_catalog_connection_no_secrets import (
                    glue_catalog_connection_no_secrets,
                )

                check = glue_catalog_connection_no_secrets()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert "Potential secret" in result[0].status_extended
                assert connection_name in result[0].status_extended
                assert "in property PASSWORD" in result[0].status_extended
                assert result[0].resource_id == connection_name

    @mock_aws
    def test_glue_connection_empty_properties(self):
        glue_client = client("glue", region_name=AWS_REGION_US_EAST_1)
        connection_name = "test-connection"

        glue_client.create_connection(
            ConnectionInput={
                "Name": connection_name,
                "ConnectionType": "JDBC",
                "ConnectionProperties": {},
            }
        )

        from prowler.providers.aws.services.glue.glue_service import Glue

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.glue.glue_catalog_connection_no_secrets.glue_catalog_connection_no_secrets.glue_client",
                new=Glue(aws_provider),
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
                    == f"No secrets found in Glue Data Catalog connection {connection_name} properties."
                )
                assert result[0].resource_id == connection_name
