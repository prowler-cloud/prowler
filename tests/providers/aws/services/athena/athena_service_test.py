import pytest
from botocore.client import BaseClient
from botocore.stub import Stubber
from mock import patch
from moto import mock_aws

from prowler.providers.aws.services.athena.athena_service import Athena
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

# Mocking Access Analyzer Calls
make_api_call = BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """
    Mock every AWS API call using Boto3

    As you can see the operation_name has the get_work_group snake_case form but
    we are using the GetWorkGroup form.
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816
    """
    if operation_name == "GetWorkGroup":
        return {
            "WorkGroup": {
                "Name": "primary",
                "State": "ENABLED",
                "Configuration": {
                    "ResultConfiguration": {
                        "EncryptionConfiguration": {
                            "EncryptionOption": "SSE_S3",
                        },
                    },
                    "EnforceWorkGroupConfiguration": True,
                    "PublishCloudWatchMetricsEnabled": True,
                },
            }
        }
    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_Athena_Service:
    @pytest.mark.parametrize(
        "first_page_has_workgroup, filter_resources, expected_names",
        [
            (True, False, {"first", "second"}),
            (False, False, {"second"}),
            (True, True, {"second"}),
        ],
        ids=["multiple-pages", "empty-first-page", "filtered-later-page"],
    )
    @mock_aws
    def test_list_workgroups_paginated(
        self, first_page_has_workgroup, filter_resources, expected_names
    ):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        athena = Athena(aws_provider)
        athena.workgroups.clear()
        regional_client = athena.regional_clients[AWS_REGION_EU_WEST_1]
        second_arn = f"arn:aws:athena:{AWS_REGION_EU_WEST_1}:{aws_provider.identity.account}:workgroup/second"
        if filter_resources:
            athena.audit_resources = [second_arn]

        with Stubber(regional_client) as stubber:
            stubber.add_response(
                "list_work_groups",
                {
                    "WorkGroups": (
                        [{"Name": "first", "State": "ENABLED"}]
                        if first_page_has_workgroup
                        else []
                    ),
                    "NextToken": "next-page",
                },
                {},
            )
            stubber.add_response(
                "list_work_groups",
                {"WorkGroups": [{"Name": "second", "State": "DISABLED"}]},
                {"NextToken": "next-page"},
            )

            athena._list_workgroups(regional_client)

            assert {
                group.name for group in athena.workgroups.values()
            } == expected_names
            assert athena.workgroups[second_arn].state == "DISABLED"
            assert athena.workgroups[second_arn].region == AWS_REGION_EU_WEST_1
            stubber.assert_no_pending_responses()

    @mock_aws
    def test_list_workgroups_empty(self):
        athena = Athena(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        athena.workgroups.clear()
        regional_client = athena.regional_clients[AWS_REGION_EU_WEST_1]

        with Stubber(regional_client) as stubber:
            stubber.add_response("list_work_groups", {"WorkGroups": []}, {})

            athena._list_workgroups(regional_client)

            assert athena.workgroups == {}
            stubber.assert_no_pending_responses()

    @mock_aws
    def test_list_workgroups_later_page_error(self, caplog):
        athena = Athena(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        athena.workgroups.clear()
        regional_client = athena.regional_clients[AWS_REGION_EU_WEST_1]
        caplog.clear()

        with Stubber(regional_client) as stubber:
            stubber.add_response(
                "list_work_groups",
                {
                    "WorkGroups": [{"Name": "first", "State": "ENABLED"}],
                    "NextToken": "next-page",
                },
                {},
            )
            stubber.add_client_error(
                "list_work_groups",
                service_error_code="InternalServerException",
                service_message="Unable to list the next page",
                expected_params={"NextToken": "next-page"},
            )

            athena._list_workgroups(regional_client)

            assert {group.name for group in athena.workgroups.values()} == {"first"}
            assert "InternalServerException" in caplog.text
            assert "Unable to list the next page" in caplog.text
            stubber.assert_no_pending_responses()

    # Test Athena Get Workgrups
    @mock_aws
    def test_get_workgroupsnot_encrypted(self):
        default_workgroup_name = "primary"
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        workgroup_arn = f"arn:{aws_provider.identity.partition}:athena:{AWS_REGION_EU_WEST_1}:{aws_provider.identity.account}:workgroup/{default_workgroup_name}"
        athena = Athena(aws_provider)
        assert len(athena.workgroups) == 1
        assert athena.workgroups[workgroup_arn]
        assert athena.workgroups[workgroup_arn].arn == workgroup_arn
        assert athena.workgroups[workgroup_arn].name == default_workgroup_name
        assert athena.workgroups[workgroup_arn].region == AWS_REGION_EU_WEST_1
        assert athena.workgroups[workgroup_arn].tags == []
        assert (
            athena.workgroups[workgroup_arn].encryption_configuration.encrypted is False
        )
        assert (
            athena.workgroups[workgroup_arn].encryption_configuration.encryption_option
            == ""
        )
        assert athena.workgroups[workgroup_arn].enforce_workgroup_configuration is False

    # Test Athena Get Workgrups
    # We mock the get_work_group to return an encrypted workgroup
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_get_workgroupsencrypted(self):
        default_workgroup_name = "primary"
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        # Athena client
        # This API call is not implemented by Moto
        # athena_client = aws_provider.audit_session.client(
        #     "athena", region_name=AWS_REGION
        # )
        # athena_client.update_work_group(
        #     WorkGroup=default_workgroup_name,
        #     ConfigurationUpdates={
        #         "ResultConfigurationUpdates": {
        #             "EncryptionConfiguration": {"EncryptionOption": "SSE_S3"}
        #         }
        #     },
        # )

        workgroup_arn = f"arn:{aws_provider.identity.partition}:athena:{AWS_REGION_EU_WEST_1}:{aws_provider.identity.account}:workgroup/{default_workgroup_name}"
        athena = Athena(aws_provider)
        assert len(athena.workgroups) == 1
        assert athena.workgroups[workgroup_arn]
        assert athena.workgroups[workgroup_arn].arn == workgroup_arn
        assert athena.workgroups[workgroup_arn].name == default_workgroup_name
        assert athena.workgroups[workgroup_arn].region == AWS_REGION_EU_WEST_1
        assert athena.workgroups[workgroup_arn].tags == []
        assert (
            athena.workgroups[workgroup_arn].encryption_configuration.encrypted is True
        )
        assert (
            athena.workgroups[workgroup_arn].encryption_configuration.encryption_option
            == "SSE_S3"
        )
        assert athena.workgroups[workgroup_arn].enforce_workgroup_configuration is True
        assert athena.workgroups[workgroup_arn].cloudwatch_logging
