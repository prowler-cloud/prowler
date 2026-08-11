from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_glue_connection_no_secrets:
    @mock_aws
    def test_glue_no_connections(self):
        from prowler.providers.aws.services.glue.glue_service import Glue

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.glue.glue_connection_no_secrets.glue_connection_no_secrets.glue_client",
                new=Glue(aws_provider),
            ):
                from prowler.providers.aws.services.glue.glue_connection_no_secrets.glue_connection_no_secrets import (
                    glue_connection_no_secrets,
                )

                check = glue_connection_no_secrets()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_glue_connection_no_secrets(self):
        glue = client("glue", region_name=AWS_REGION_US_EAST_1)
        connection_name = "test-connection"
        connection_arn = f"arn:aws:glue:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:connection/{connection_name}"
        glue.create_connection(
            ConnectionInput={
                "Name": connection_name,
                "ConnectionType": "JDBC",
                "ConnectionProperties": {
                    "JDBC_CONNECTION_URL": "jdbc:mysql://my-rds.example.com:3306/mydb",
                    # SECRET_ID references a Secrets Manager secret — no plaintext credential.
                    "SECRET_ID": f"arn:aws:secretsmanager:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:secret:my-db-secret",
                },
                "PhysicalConnectionRequirements": {
                    "SubnetId": "subnet-12345",
                    "SecurityGroupIdList": ["sg-12345"],
                    "AvailabilityZone": f"{AWS_REGION_US_EAST_1}a",
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
                "prowler.providers.aws.services.glue.glue_connection_no_secrets.glue_connection_no_secrets.glue_client",
                new=Glue(aws_provider),
            ):
                from prowler.providers.aws.services.glue.glue_connection_no_secrets.glue_connection_no_secrets import (
                    glue_connection_no_secrets,
                )

                check = glue_connection_no_secrets()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"No secrets found in Glue connection {connection_name} properties."
                )
                assert result[0].resource_id == connection_name
                assert result[0].resource_arn == connection_arn

    @mock_aws
    def test_glue_connection_with_secrets(self):
        glue = client("glue", region_name=AWS_REGION_US_EAST_1)
        connection_name = "test-connection-with-password"
        connection_arn = f"arn:aws:glue:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:connection/{connection_name}"
        glue.create_connection(
            ConnectionInput={
                "Name": connection_name,
                "ConnectionType": "JDBC",
                "ConnectionProperties": {
                    "JDBC_CONNECTION_URL": "jdbc:mysql://my-rds.example.com:3306/mydb",
                    # Hardcoded password — the pattern that triggers a FAIL.
                    "PASSWORD": "AKIAsupersecretkey1234",
                    "USERNAME": "admin",
                },
                "PhysicalConnectionRequirements": {
                    "SubnetId": "subnet-12345",
                    "SecurityGroupIdList": ["sg-12345"],
                    "AvailabilityZone": f"{AWS_REGION_US_EAST_1}a",
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
                "prowler.providers.aws.services.glue.glue_connection_no_secrets.glue_connection_no_secrets.glue_client",
                new=Glue(aws_provider),
            ):
                from prowler.providers.aws.services.glue.glue_connection_no_secrets.glue_connection_no_secrets import (
                    glue_connection_no_secrets,
                )

                check = glue_connection_no_secrets()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert "Potential secrets found" in result[0].status_extended
                assert connection_name in result[0].status_extended
                assert "PASSWORD" in result[0].status_extended
                assert result[0].resource_id == connection_name
                assert result[0].resource_arn == connection_arn

    @mock_aws
    def test_glue_connection_empty_properties(self):
        glue = client("glue", region_name=AWS_REGION_US_EAST_1)
        connection_name = "test-connection-empty"
        connection_arn = f"arn:aws:glue:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:connection/{connection_name}"
        glue.create_connection(
            ConnectionInput={
                "Name": connection_name,
                "ConnectionType": "NETWORK",
                "ConnectionProperties": {},
                "PhysicalConnectionRequirements": {
                    "SubnetId": "subnet-12345",
                    "SecurityGroupIdList": ["sg-12345"],
                    "AvailabilityZone": f"{AWS_REGION_US_EAST_1}a",
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
                "prowler.providers.aws.services.glue.glue_connection_no_secrets.glue_connection_no_secrets.glue_client",
                new=Glue(aws_provider),
            ):
                from prowler.providers.aws.services.glue.glue_connection_no_secrets.glue_connection_no_secrets import (
                    glue_connection_no_secrets,
                )

                check = glue_connection_no_secrets()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"No secrets found in Glue connection {connection_name} properties."
                )
                assert result[0].resource_id == connection_name
                assert result[0].resource_arn == connection_arn
