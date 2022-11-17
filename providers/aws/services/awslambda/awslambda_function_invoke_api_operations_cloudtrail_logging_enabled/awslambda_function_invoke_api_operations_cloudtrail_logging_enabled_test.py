# from datetime import datetime
# from unittest import mock

# from boto3 import session
# from moto.core import DEFAULT_ACCOUNT_ID

# from providers.aws.lib.audit_info.audit_info import AWS_Audit_Info
# from providers.aws.services.awslambda.awslambda_service import Function
# from providers.aws.services.cloudtrail.cloudtrail_service import Trail

# AWS_REGION = "us-east-1"


# class Test_awslambda_function_invoke_api_operations_cloudtrail_logging_enabled:
#     # Mocked Audit Info
#     def set_mocked_audit_info(self):
#         audit_info = AWS_Audit_Info(
#             original_session=None,
#             audit_session=session.Session(
#                 profile_name=None,
#                 botocore_session=None,
#             ),
#             audited_account=None,
#             audited_user_id=None,
#             audited_partition="aws",
#             audited_identity_arn=None,
#             profile=None,
#             profile_region=None,
#             credentials=None,
#             assumed_role_info=None,
#             audited_regions=None,
#             organizations_metadata=None,
#         )
#         return audit_info

#     def test_no_functions(self):
#         lambda_client = mock.MagicMock
#         lambda_client.functions = {}
#         cloudtrail_client = mock.MagicMock
#         cloudtrail_client.trails = []

#         with mock.patch(
#             "providers.aws.services.awslambda.awslambda_service.Lambda",
#             new=lambda_client,
#         ), mock.patch(
#             "providers.aws.lib.audit_info.audit_info.current_audit_info",
#             self.set_mocked_audit_info(),
#         ), mock.patch(
#             "providers.aws.services.cloudtrail.cloudtrail_service.Cloudtrail",
#             new=cloudtrail_client,
#         ):
#             # Test Check
#             from providers.aws.services.awslambda.awslambda_function_invoke_api_operations_cloudtrail_logging_enabled.awslambda_function_invoke_api_operations_cloudtrail_logging_enabled import (
#                 awslambda_function_invoke_api_operations_cloudtrail_logging_enabled,
#             )

#             check = (
#                 awslambda_function_invoke_api_operations_cloudtrail_logging_enabled()
#             )
#             result = check.execute()

#             assert len(result) == 0

#     def test_lambda_not_recorded_by_cloudtrail(self):
#         # Lambda Client
#         lambda_client = mock.MagicMock
#         function_name = "test-lambda"
#         function_runtime = "python3.9"
#         function_arn = (
#             f"arn:aws:lambda:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:function/{function_name}"
#         )
#         lambda_client.functions = {
#             function_name: Function(
#                 name=function_name,
#                 arn=function_arn,
#                 region=AWS_REGION,
#                 runtime=function_runtime,
#             )
#         }
#         # CloudTrail Client
#         cloudtrail_client = mock.MagicMock
#         cloudtrail_client.trails = [
#             Trail(
#                 name="test-trail",
#                 is_multiregion=False,
#                 home_region=AWS_REGION,
#                 arn="",
#                 region=AWS_REGION,
#                 is_logging=True,
#                 log_file_validation_enabled=True,
#                 latest_cloudwatch_delivery_time=datetime(2022, 1, 1),
#                 s3_bucket="",
#                 kms_key="",
#                 log_group_arn="",
#                 data_events=[
#                     {
#                         "ReadWriteType": "All",
#                         "IncludeManagementEvents": True,
#                         "DataResources": [],
#                         "ExcludeManagementEventSources": [],
#                     }
#                 ],
#             )
#         ]

#         with mock.patch(
#             "providers.aws.services.awslambda.awslambda_service.Lambda",
#             new=lambda_client,
#         ), mock.patch(
#             "providers.aws.services.cloudtrail.cloudtrail_service.Cloudtrail",
#             new=cloudtrail_client,
#         ):

#             # Test Check
#             from providers.aws.services.awslambda.awslambda_function_invoke_api_operations_cloudtrail_logging_enabled.awslambda_function_invoke_api_operations_cloudtrail_logging_enabled import (
#                 awslambda_function_invoke_api_operations_cloudtrail_logging_enabled,
#             )

#             check = (
#                 awslambda_function_invoke_api_operations_cloudtrail_logging_enabled()
#             )
#             result = check.execute()

#             assert len(result) == 1
#             assert result[0].region == AWS_REGION
#             assert result[0].resource_id == function_name
#             assert result[0].resource_arn == function_arn
#             assert result[0].status == "FAIL"
#             assert (
#                 result[0].status_extended
#                 == f"Lambda function {function_name} is not recorded by CloudTrail"
#             )

#     def test_lambda_recorded_by_cloudtrail(self):
#         # Lambda Client
#         lambda_client = mock.MagicMock
#         function_name = "test-lambda"
#         function_runtime = "python3.9"
#         function_arn = (
#             f"arn:aws:lambda:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:function/{function_name}"
#         )
#         lambda_client.functions = {
#             function_name: Function(
#                 name=function_name,
#                 arn=function_arn,
#                 region=AWS_REGION,
#                 runtime=function_runtime,
#             )
#         }
#         # CloudTrail Client
#         cloudtrail_client = mock.MagicMock
#         trail_name = "test-trail"
#         cloudtrail_client.trails = [
#             Trail(
#                 name=trail_name,
#                 is_multiregion=False,
#                 home_region=AWS_REGION,
#                 arn="",
#                 region=AWS_REGION,
#                 is_logging=True,
#                 log_file_validation_enabled=True,
#                 latest_cloudwatch_delivery_time=datetime(2022, 1, 1),
#                 s3_bucket="",
#                 kms_key="",
#                 log_group_arn="",
#                 data_events=[
#                     {
#                         "ReadWriteType": "All",
#                         "IncludeManagementEvents": True,
#                         "DataResources": [
#                             {
#                                 "Type": "AWS::Lambda::Function",
#                                 "Values": [
#                                     function_arn,
#                                 ],
#                             },
#                         ],
#                         "ExcludeManagementEventSources": [],
#                     }
#                 ],
#             )
#         ]

#         with mock.patch(
#             "providers.aws.services.awslambda.awslambda_service.Lambda",
#             new=lambda_client,
#         ), mock.patch(
#             "providers.aws.services.cloudtrail.cloudtrail_service.Cloudtrail",
#             new=cloudtrail_client,
#         ):

#             #
#             # Test Check
#             from providers.aws.services.awslambda.awslambda_function_invoke_api_operations_cloudtrail_logging_enabled.awslambda_function_invoke_api_operations_cloudtrail_logging_enabled import (
#                 awslambda_function_invoke_api_operations_cloudtrail_logging_enabled,
#             )

#             check = (
#                 awslambda_function_invoke_api_operations_cloudtrail_logging_enabled()
#             )
#             result = check.execute()

#             assert len(result) == 1
#             assert result[0].region == AWS_REGION
#             assert result[0].resource_id == function_name
#             assert result[0].resource_arn == function_arn
#             assert result[0].status == "PASS"
#             assert (
#                 result[0].status_extended
#                 == f"Lambda function {function_name} is recorded by CloudTrail {trail_name}"
#             )
