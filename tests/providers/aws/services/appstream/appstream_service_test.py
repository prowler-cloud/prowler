from unittest.mock import patch

import botocore
from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.services.appstream.appstream_service import AppStream
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

# Mock Test Region
AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """
    We have to mock every AWS API call using Boto3

    As you can see the operation_name has the list_analyzers snake_case form but
    we are using the ListAnalyzers form.
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816
    """
    if operation_name == "DescribeFleets":
        return {
            "Fleets": [
                {
                    "Arn": f"arn:aws:appstream:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:fleet/test-prowler3-0",
                    "Name": "test-prowler3-0",
                    "MaxUserDurationInSeconds": 100,
                    "DisconnectTimeoutInSeconds": 900,
                    "IdleDisconnectTimeoutInSeconds": 900,
                    "EnableDefaultInternetAccess": False,
                },
                {
                    "Arn": f"arn:aws:appstream:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:fleet/test-prowler3-1",
                    "Name": "test-prowler3-1",
                    "MaxUserDurationInSeconds": 57600,
                    "DisconnectTimeoutInSeconds": 900,
                    "IdleDisconnectTimeoutInSeconds": 900,
                    "EnableDefaultInternetAccess": True,
                },
            ]
        }
    if operation_name == "ListTagsForResource":
        return {"Tags": {"test": "test"}}
    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(service, audit_info, _):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_AppStream_Service:
    # Test AppStream Client
    def test__get_client__(self):
        appstream = AppStream(set_mocked_aws_audit_info([AWS_REGION_US_EAST_1]))
        assert appstream.regional_clients[AWS_REGION].__class__.__name__ == "AppStream"

    # Test AppStream Session
    def test__get_session__(self):
        appstream = AppStream(set_mocked_aws_audit_info([AWS_REGION_US_EAST_1]))
        assert appstream.session.__class__.__name__ == "Session"

    # Test AppStream Session
    def test__get_service__(self):
        appstream = AppStream(set_mocked_aws_audit_info([AWS_REGION_US_EAST_1]))
        assert appstream.service == "appstream"

    def test__describe_fleets__(self):
        # Set partition for the service
        appstream = AppStream(set_mocked_aws_audit_info([AWS_REGION_US_EAST_1]))
        assert len(appstream.fleets) == 2

        assert (
            appstream.fleets[0].arn
            == f"arn:aws:appstream:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:fleet/test-prowler3-0"
        )
        assert appstream.fleets[0].name == "test-prowler3-0"
        assert appstream.fleets[0].max_user_duration_in_seconds == 100
        assert appstream.fleets[0].disconnect_timeout_in_seconds == 900
        assert appstream.fleets[0].idle_disconnect_timeout_in_seconds == 900
        assert appstream.fleets[0].enable_default_internet_access is False
        assert appstream.fleets[0].region == AWS_REGION

        assert (
            appstream.fleets[1].arn
            == f"arn:aws:appstream:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:fleet/test-prowler3-1"
        )
        assert appstream.fleets[1].name == "test-prowler3-1"
        assert appstream.fleets[1].max_user_duration_in_seconds == 57600
        assert appstream.fleets[1].disconnect_timeout_in_seconds == 900
        assert appstream.fleets[1].idle_disconnect_timeout_in_seconds == 900
        assert appstream.fleets[1].enable_default_internet_access is True
        assert appstream.fleets[1].region == AWS_REGION

    def test__list_tags_for_resource__(self):
        # Set partition for the service
        appstream = AppStream(set_mocked_aws_audit_info([AWS_REGION_US_EAST_1]))
        assert len(appstream.fleets) == 2

        assert appstream.fleets[0].tags == [{"test": "test"}]

        assert appstream.fleets[1].tags == [{"test": "test"}]
