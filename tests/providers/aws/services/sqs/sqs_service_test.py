from json import dumps
from unittest.mock import patch
from uuid import uuid4

import botocore
from boto3 import client, session
from moto import mock_sqs

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.sqs.sqs_service import SQS
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "eu-west-1"

test_queue = "test-queue"
test_key = str(uuid4())
test_queue_arn = f"arn:aws:sqs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:{test_queue}"
test_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "sqs:SendMessage",
            "Resource": test_queue_arn,
        }
    ],
}

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "GetQueueAttributes":
        return {
            "Attributes": {"Policy": dumps(test_policy), "KmsMasterKeyId": test_key}
        }
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(service, audit_info, _):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_SQS_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    # Test SQS Service
    def test_service(self):
        audit_info = self.set_mocked_audit_info()
        sqs = SQS(audit_info)
        assert sqs.service == "sqs"

    # Test SQS client
    def test_client(self):
        audit_info = self.set_mocked_audit_info()
        sqs = SQS(audit_info)
        for reg_client in sqs.regional_clients.values():
            assert reg_client.__class__.__name__ == "SQS"

    # Test SQS session
    def test__get_session__(self):
        audit_info = self.set_mocked_audit_info()
        sqs = SQS(audit_info)
        assert sqs.session.__class__.__name__ == "Session"

    @mock_sqs
    # Test SQS list queues
    def test__list_queues__(self):
        sqs_client = client("sqs", region_name=AWS_REGION)
        queue = sqs_client.create_queue(QueueName=test_queue, tags={"test": "test"})
        audit_info = self.set_mocked_audit_info()
        sqs = SQS(audit_info)
        assert len(sqs.queues) == 1
        assert sqs.queues[0].id == queue["QueueUrl"]
        assert sqs.queues[0].name == test_queue
        assert sqs.queues[0].name == sqs.queues[0].arn.split(":")[-1]
        assert sqs.queues[0].name == sqs.queues[0].id.split("/")[-1]
        assert sqs.queues[0].arn == test_queue_arn
        assert sqs.queues[0].region == AWS_REGION
        assert sqs.queues[0].tags == [{"test": "test"}]

    @mock_sqs
    # Test SQS list queues
    def test__get_queue_attributes__(self):
        sqs_client = client("sqs", region_name=AWS_REGION)
        queue = sqs_client.create_queue(
            QueueName=test_queue,
        )
        audit_info = self.set_mocked_audit_info()
        sqs = SQS(audit_info)
        assert len(sqs.queues) == 1
        assert sqs.queues[0].id == queue["QueueUrl"]
        assert sqs.queues[0].region == AWS_REGION
        assert sqs.queues[0].policy
        assert sqs.queues[0].kms_key_id == test_key
