from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.mq.mq_service import MQ, DeploymentMode, EngineType
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider


class Test_MQ_Service:
    # Test MQ Service
    @mock_aws
    def test_service(self):
        # MQ client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        mq = MQ(aws_provider)
        assert mq.service == "mq"

    # Test MQ Client
    @mock_aws
    def test_client(self):
        # MQ client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        mq = MQ(aws_provider)
        for regional_client in mq.regional_clients.values():
            assert regional_client.__class__.__name__ == "MQ"

    # Test MQ Session
    @mock_aws
    def test__get_session__(self):
        # MQ client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        mq = MQ(aws_provider)
        assert mq.session.__class__.__name__ == "Session"

    # Test MQ List Brokers
    @mock_aws
    def test_list_brokers(self):
        # Generate MQ client
        mq_client = client("mq", region_name=AWS_REGION_EU_WEST_1)
        broker = mq_client.create_broker(
            AutoMinorVersionUpgrade=True,
            BrokerName="my-broker",
            DeploymentMode="SINGLE_INSTANCE",
            EngineType="ActiveMQ",
            EngineVersion="5.15.0",
            HostInstanceType="mq.t2.micro",
            PubliclyAccessible=True,
            Users=[
                {
                    "ConsoleAccess": False,
                    "Groups": [],
                    "Password": "password",
                    "Username": "user",
                }
            ],
        )
        broker_arn = broker["BrokerArn"]

        # MQ Client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        mq = MQ(aws_provider)

        assert len(mq.brokers) == 1
        assert mq.brokers[broker_arn].arn == broker_arn
        assert mq.brokers[broker_arn].name == "my-broker"
        assert mq.brokers[broker_arn].region == AWS_REGION_EU_WEST_1
        assert mq.brokers[broker_arn].id == broker["BrokerId"]

    # Test MQ Describe Broker
    @mock_aws
    def test_describe_broker(self):
        # Generate MQ client
        mq_client = client("mq", region_name=AWS_REGION_EU_WEST_1)
        broker = mq_client.create_broker(
            AutoMinorVersionUpgrade=True,
            BrokerName="my-broker",
            DeploymentMode="SINGLE_INSTANCE",
            EngineType="ACTIVEMQ",
            EngineVersion="5.15.0",
            HostInstanceType="mq.t2.micro",
            PubliclyAccessible=True,
            Users=[
                {
                    "ConsoleAccess": False,
                    "Groups": [],
                    "Password": "password",
                    "Username": "user",
                }
            ],
        )
        broker_arn = broker["BrokerArn"]
        broker["BrokerId"]

        mq_client.create_tags(
            ResourceArn=broker_arn,
            Tags={
                "key": "value",
            },
        )

        # MQ Client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        mq = MQ(aws_provider)

        assert len(mq.brokers) == 1
        assert mq.brokers[broker_arn].arn == broker_arn
        assert mq.brokers[broker_arn].name == "my-broker"
        assert mq.brokers[broker_arn].region == AWS_REGION_EU_WEST_1
        assert mq.brokers[broker_arn].id == broker["BrokerId"]
        assert mq.brokers[broker_arn].engine_type == EngineType.ACTIVEMQ
        assert mq.brokers[broker_arn].deployment_mode == DeploymentMode.SINGLE_INSTANCE
        assert mq.brokers[broker_arn].auto_minor_version_upgrade
        assert mq.brokers[broker_arn].publicly_accessible
        assert mq.brokers[broker_arn].tags == [{"key": "value"}]
