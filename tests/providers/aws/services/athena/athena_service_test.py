from botocore.client import BaseClient
from mock import patch
from moto import mock_aws

from prowler.providers.aws.services.athena.athena_service import Athena
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

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
                },
            }
        }
    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_Athena_Service:
    # Test Athena Get Workgrups
    @mock_aws
    def test__get_workgroups__not_encrypted(self):
        default_workgroup_name = "primary"
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        workgroup_arn = f"arn:{audit_info.audited_partition}:athena:{AWS_REGION_EU_WEST_1}:{audit_info.audited_account}:workgroup/{default_workgroup_name}"
        athena = Athena(audit_info)
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
    def test__get_workgroups__encrypted(self):
        default_workgroup_name = "primary"
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        # Athena client
        # This API call is not implemented by Moto
        # athena_client = audit_info.audit_session.client(
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

        workgroup_arn = f"arn:{audit_info.audited_partition}:athena:{AWS_REGION_EU_WEST_1}:{audit_info.audited_account}:workgroup/{default_workgroup_name}"
        athena = Athena(audit_info)
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
