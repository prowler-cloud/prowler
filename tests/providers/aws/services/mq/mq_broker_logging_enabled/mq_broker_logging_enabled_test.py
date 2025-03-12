from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_mq_broker_logging_enabled:
    @mock_aws
    def test_no_brokers(self):
        from prowler.providers.aws.services.mq.mq_service import MQ

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.mq.mq_broker_logging_enabled.mq_broker_logging_enabled.mq_client",
            new=MQ(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.mq.mq_broker_logging_enabled.mq_broker_logging_enabled import (
                mq_broker_logging_enabled,
            )

            check = mq_broker_logging_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_rabbitmq_broker_logging_enabled(self):
        mq_client = client("mq", region_name=AWS_REGION_US_EAST_1)
        broker_name = "test-broker"
        engine_type = "RABBITMQ"
        broker_id = mq_client.create_broker(
            BrokerName=broker_name,
            EngineType=engine_type,
            EngineVersion="5.15.0",
            HostInstanceType="mq.t2.micro",
            Users=[
                {
                    "Username": "admin",
                    "Password": "admin",
                },
            ],
            DeploymentMode="SINGLE_INSTANCE",
            PubliclyAccessible=False,
            AutoMinorVersionUpgrade=True,
            Logs={
                "General": True,
            },
        )["BrokerId"]

        from prowler.providers.aws.services.mq.mq_service import MQ

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.mq.mq_broker_logging_enabled.mq_broker_logging_enabled.mq_client",
            new=MQ(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.mq.mq_broker_logging_enabled.mq_broker_logging_enabled import (
                mq_broker_logging_enabled,
            )

            check = mq_broker_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"MQ Broker {broker_name} does have logging enabled."
            )
            assert result[0].resource_id == broker_id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:mq:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:broker:{broker_id}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_rabbitmq_broker_logging_disabled(self):
        mq_client = client("mq", region_name=AWS_REGION_US_EAST_1)
        broker_name = "test-broker"
        engine_type = "RABBITMQ"
        broker_id = mq_client.create_broker(
            BrokerName=broker_name,
            EngineType=engine_type,
            EngineVersion="5.15.0",
            HostInstanceType="mq.t2.micro",
            Users=[
                {
                    "Username": "admin",
                    "Password": "admin",
                },
            ],
            DeploymentMode="SINGLE_INSTANCE",
            PubliclyAccessible=False,
            AutoMinorVersionUpgrade=True,
            Logs={
                "General": False,
            },
        )["BrokerId"]

        from prowler.providers.aws.services.mq.mq_service import MQ

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.mq.mq_broker_logging_enabled.mq_broker_logging_enabled.mq_client",
            new=MQ(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.mq.mq_broker_logging_enabled.mq_broker_logging_enabled import (
                mq_broker_logging_enabled,
            )

            check = mq_broker_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"MQ Broker {broker_name} does not have logging enabled."
            )
            assert result[0].resource_id == broker_id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:mq:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:broker:{broker_id}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_activemq_broker_logging_enabled(self):
        mq_client = client("mq", region_name=AWS_REGION_US_EAST_1)
        broker_name = "test-broker"
        engine_type = "ACTIVEMQ"
        broker_id = mq_client.create_broker(
            BrokerName=broker_name,
            EngineType=engine_type,
            EngineVersion="5.15.0",
            HostInstanceType="mq.t2.micro",
            Users=[
                {
                    "Username": "admin",
                    "Password": "admin",
                },
            ],
            DeploymentMode="SINGLE_INSTANCE",
            PubliclyAccessible=False,
            AutoMinorVersionUpgrade=True,
            Logs={
                "General": True,
                "Audit": True,
            },
        )["BrokerId"]

        from prowler.providers.aws.services.mq.mq_service import MQ

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.mq.mq_broker_logging_enabled.mq_broker_logging_enabled.mq_client",
            new=MQ(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.mq.mq_broker_logging_enabled.mq_broker_logging_enabled import (
                mq_broker_logging_enabled,
            )

            check = mq_broker_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"MQ Broker {broker_name} does have logging enabled."
            )
            assert result[0].resource_id == broker_id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:mq:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:broker:{broker_id}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_activemq_broker_logging_disabled(self):
        mq_client = client("mq", region_name=AWS_REGION_US_EAST_1)
        broker_name = "test-broker"
        engine_type = "ACTIVEMQ"
        broker_id = mq_client.create_broker(
            BrokerName=broker_name,
            EngineType=engine_type,
            EngineVersion="5.15.0",
            HostInstanceType="mq.t2.micro",
            Users=[
                {
                    "Username": "admin",
                    "Password": "admin",
                },
            ],
            DeploymentMode="SINGLE_INSTANCE",
            PubliclyAccessible=False,
            AutoMinorVersionUpgrade=True,
            Logs={
                "General": True,
                "Audit": False,
            },
        )["BrokerId"]

        from prowler.providers.aws.services.mq.mq_service import MQ

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.mq.mq_broker_logging_enabled.mq_broker_logging_enabled.mq_client",
            new=MQ(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.mq.mq_broker_logging_enabled.mq_broker_logging_enabled import (
                mq_broker_logging_enabled,
            )

            check = mq_broker_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"MQ Broker {broker_name} does not have logging enabled."
            )
            assert result[0].resource_id == broker_id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:mq:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:broker:{broker_id}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
