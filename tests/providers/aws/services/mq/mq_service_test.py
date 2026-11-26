from boto3 import client
from botocore.stub import Stubber
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

    @mock_aws
    def test_list_brokers_pagination(self):
        mq = MQ(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        regional_client = mq.regional_clients[AWS_REGION_EU_WEST_1]
        brokers = [
            {
                "BrokerArn": f"arn:aws:mq:{AWS_REGION_EU_WEST_1}:123456789012:broker:broker-{i}:b-{i}",
                "BrokerName": f"broker-{i}",
                "BrokerId": f"b-{i}",
                "DeploymentMode": "SINGLE_INSTANCE",
                "EngineType": "ACTIVEMQ",
            }
            for i in range(2)
        ]
        with Stubber(regional_client) as stubber:
            stubber.add_response(
                "list_brokers",
                {"BrokerSummaries": [brokers[0]], "NextToken": "next"},
                {},
            )
            stubber.add_response(
                "list_brokers",
                {"BrokerSummaries": [], "NextToken": "last"},
                {"NextToken": "next"},
            )
            stubber.add_response(
                "list_brokers", {"BrokerSummaries": [brokers[1]]}, {"NextToken": "last"}
            )
            mq._list_brokers(regional_client)
            assert set(mq.brokers) == {broker["BrokerArn"] for broker in brokers}
            assert mq.brokers[brokers[1]["BrokerArn"]].id == "b-1"
            assert mq.brokers[brokers[1]["BrokerArn"]].region == AWS_REGION_EU_WEST_1
            stubber.assert_no_pending_responses()

    @mock_aws
    def test_list_brokers_pagination_resource_filter(self):
        mq = MQ(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        regional_client = mq.regional_clients[AWS_REGION_EU_WEST_1]
        brokers = [
            {
                "BrokerArn": f"arn:aws:mq:{AWS_REGION_EU_WEST_1}:123456789012:broker:broker-{i}:b-{i}",
                "BrokerName": f"broker-{i}",
                "BrokerId": f"b-{i}",
                "DeploymentMode": "SINGLE_INSTANCE",
                "EngineType": "ACTIVEMQ",
            }
            for i in range(2)
        ]
        mq.audit_resources = [brokers[1]["BrokerArn"]]
        with Stubber(regional_client) as stubber:
            stubber.add_response(
                "list_brokers",
                {"BrokerSummaries": [brokers[0]], "NextToken": "next"},
                {},
            )
            stubber.add_response(
                "list_brokers", {"BrokerSummaries": [brokers[1]]}, {"NextToken": "next"}
            )
            mq._list_brokers(regional_client)
            assert set(mq.brokers) == {brokers[1]["BrokerArn"]}
            stubber.assert_no_pending_responses()

    @mock_aws
    def test_list_brokers_keeps_previous_page_on_error(self):
        mq = MQ(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        regional_client = mq.regional_clients[AWS_REGION_EU_WEST_1]
        broker = {
            "BrokerArn": f"arn:aws:mq:{AWS_REGION_EU_WEST_1}:123456789012:broker:broker-0:b-0",
            "BrokerName": "broker-0",
            "BrokerId": "b-0",
            "DeploymentMode": "SINGLE_INSTANCE",
            "EngineType": "ACTIVEMQ",
        }
        with Stubber(regional_client) as stubber:
            stubber.add_response(
                "list_brokers", {"BrokerSummaries": [broker], "NextToken": "next"}, {}
            )
            stubber.add_client_error(
                "list_brokers",
                service_error_code="AccessDeniedException",
                expected_params={"NextToken": "next"},
            )
            mq._list_brokers(regional_client)
            assert set(mq.brokers) == {broker["BrokerArn"]}
            stubber.assert_no_pending_responses()
