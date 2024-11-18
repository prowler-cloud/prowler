from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

DMS_ENDPOINT_NAME = "dms-endpoint"
DMS_ENDPOINT_ARN = f"arn:aws:dms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:endpoint:{DMS_ENDPOINT_NAME}"
DMS_INSTANCE_NAME = "rep-instance"
DMS_INSTANCE_ARN = (
    f"arn:aws:dms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rep:{DMS_INSTANCE_NAME}"
)


class Test_dms_replication_task_target_logging_enabled:
    @mock_aws
    def test_no_dms_replication_tasks(self):
        dms_client = client("dms", region_name=AWS_REGION_US_EAST_1)
        dms_client.replication_tasks = {}

        from prowler.providers.aws.services.dms.dms_service import DMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled.dms_client",
            new=DMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled import (
                dms_replication_task_target_logging_enabled,
            )

            check = dms_replication_task_target_logging_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_dms_replication_task_logging_not_enabled(self):
        dms_client = client("dms", region_name=AWS_REGION_US_EAST_1)
        dms_client.create_replication_task(
            ReplicationTaskIdentifier="rep-task",
            SourceEndpointArn=DMS_ENDPOINT_ARN,
            TargetEndpointArn=DMS_ENDPOINT_ARN,
            MigrationType="full-load",
            ReplicationTaskSettings="""
                {
                    "Logging": {
                        "EnableLogging": false,
                        "LogComponents": [
                            {
                                "Id": "TARGET_LOAD",
                                "Severity": "LOGGER_SEVERITY_DEFAULT"
                            }
                        ]
                    }
                }
            """,
            TableMappings="",
            ReplicationInstanceArn=DMS_INSTANCE_ARN,
        )

        dms_replication_task_arn = dms_client.describe_replication_tasks()[
            "ReplicationTasks"
        ][0]["ReplicationTaskArn"]

        from prowler.providers.aws.services.dms.dms_service import DMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled.dms_client",
            new=DMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled import (
                dms_replication_task_target_logging_enabled,
            )

            check = dms_replication_task_target_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "DMS Replication Task rep-task does not have logging enabled for target events."
            )
            assert result[0].resource_id == "rep-task"
            assert result[0].resource_arn == dms_replication_task_arn
            assert result[0].resource_tags == []
            assert result[0].region == "us-east-1"

    @mock_aws
    def test_dms_replication_task_logging_enabled_source_load_only(self):
        dms_client = client("dms", region_name=AWS_REGION_US_EAST_1)
        dms_client.create_replication_task(
            ReplicationTaskIdentifier="rep-task",
            SourceEndpointArn=DMS_ENDPOINT_ARN,
            TargetEndpointArn=DMS_ENDPOINT_ARN,
            MigrationType="full-load",
            ReplicationTaskSettings="""
                {
                    "Logging": {
                        "EnableLogging": true,
                        "LogComponents": [
                            {
                                "Id": "TARGET_LOAD",
                                "Severity": "LOGGER_SEVERITY_DEFAULT"
                            }
                        ]
                    }
                }
            """,
            TableMappings="",
            ReplicationInstanceArn=DMS_INSTANCE_ARN,
        )

        dms_replication_task_arn = dms_client.describe_replication_tasks()[
            "ReplicationTasks"
        ][0]["ReplicationTaskArn"]

        from prowler.providers.aws.services.dms.dms_service import DMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled.dms_client",
            new=DMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled import (
                dms_replication_task_target_logging_enabled,
            )

            check = dms_replication_task_target_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "DMS Replication Task rep-task does not meet the minimum severity level of logging in Target Apply events."
            )
            assert result[0].resource_id == "rep-task"
            assert result[0].resource_arn == dms_replication_task_arn
            assert result[0].resource_tags == []
            assert result[0].region == "us-east-1"

    @mock_aws
    def test_dms_replication_task_logging_enabled_source_apply_only(self):
        dms_client = client("dms", region_name=AWS_REGION_US_EAST_1)
        dms_client.create_replication_task(
            ReplicationTaskIdentifier="rep-task",
            SourceEndpointArn=DMS_ENDPOINT_ARN,
            TargetEndpointArn=DMS_ENDPOINT_ARN,
            MigrationType="full-load",
            ReplicationTaskSettings="""
                {
                    "Logging": {
                        "EnableLogging": true,
                        "LogComponents": [
                            {
                                "Id": "TARGET_APPLY",
                                "Severity": "LOGGER_SEVERITY_DEFAULT"
                            }
                        ]
                    }
                }
            """,
            TableMappings="",
            ReplicationInstanceArn=DMS_INSTANCE_ARN,
        )

        dms_replication_task_arn = dms_client.describe_replication_tasks()[
            "ReplicationTasks"
        ][0]["ReplicationTaskArn"]

        from prowler.providers.aws.services.dms.dms_service import DMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled.dms_client",
            new=DMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled import (
                dms_replication_task_target_logging_enabled,
            )

            check = dms_replication_task_target_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "DMS Replication Task rep-task does not meet the minimum severity level of logging in Target Load events."
            )
            assert result[0].resource_id == "rep-task"
            assert result[0].resource_arn == dms_replication_task_arn
            assert result[0].resource_tags == []
            assert result[0].region == "us-east-1"

    @mock_aws
    def test_dms_replication_task_logging_enabled_target_load_apply_with_not_enough_severity_on_load(
        self,
    ):
        dms_client = client("dms", region_name=AWS_REGION_US_EAST_1)
        dms_client.create_replication_task(
            ReplicationTaskIdentifier="rep-task",
            SourceEndpointArn=DMS_ENDPOINT_ARN,
            TargetEndpointArn=DMS_ENDPOINT_ARN,
            MigrationType="full-load",
            ReplicationTaskSettings="""
                {
                    "Logging": {
                        "EnableLogging": true,
                        "LogComponents": [
                            {
                                "Id": "TARGET_LOAD",
                                "Severity": "LOGGER_SEVERITY_INFO"
                            },
                            {
                                "Id": "TARGET_APPLY",
                                "Severity": "LOGGER_SEVERITY_DEFAULT"
                            }
                        ]
                    }
                }
            """,
            TableMappings="",
            ReplicationInstanceArn=DMS_INSTANCE_ARN,
        )

        dms_replication_task_arn = dms_client.describe_replication_tasks()[
            "ReplicationTasks"
        ][0]["ReplicationTaskArn"]

        from prowler.providers.aws.services.dms.dms_service import DMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled.dms_client",
            new=DMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled import (
                dms_replication_task_target_logging_enabled,
            )

            check = dms_replication_task_target_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "DMS Replication Task rep-task does not meet the minimum severity level of logging in Target Load events."
            )
            assert result[0].resource_id == "rep-task"
            assert result[0].resource_arn == dms_replication_task_arn
            assert result[0].resource_tags == []
            assert result[0].region == "us-east-1"

    @mock_aws
    def test_dms_replication_task_logging_enabled_target_load_apply_with_not_enough_severity_on_apply(
        self,
    ):
        dms_client = client("dms", region_name=AWS_REGION_US_EAST_1)
        dms_client.create_replication_task(
            ReplicationTaskIdentifier="rep-task",
            SourceEndpointArn=DMS_ENDPOINT_ARN,
            TargetEndpointArn=DMS_ENDPOINT_ARN,
            MigrationType="full-load",
            ReplicationTaskSettings="""
                {
                    "Logging": {
                        "EnableLogging": true,
                        "LogComponents": [
                            {
                                "Id": "TARGET_LOAD",
                                "Severity": "LOGGER_SEVERITY_DEFAULT"
                            },
                            {
                                "Id": "TARGET_APPLY",
                                "Severity": "LOGGER_SEVERITY_INFO"
                            }
                        ]
                    }
                }
            """,
            TableMappings="",
            ReplicationInstanceArn=DMS_INSTANCE_ARN,
        )

        dms_replication_task_arn = dms_client.describe_replication_tasks()[
            "ReplicationTasks"
        ][0]["ReplicationTaskArn"]

        from prowler.providers.aws.services.dms.dms_service import DMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled.dms_client",
            new=DMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled import (
                dms_replication_task_target_logging_enabled,
            )

            check = dms_replication_task_target_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "DMS Replication Task rep-task does not meet the minimum severity level of logging in Target Apply events."
            )
            assert result[0].resource_id == "rep-task"
            assert result[0].resource_arn == dms_replication_task_arn
            assert result[0].resource_tags == []
            assert result[0].region == "us-east-1"

    @mock_aws
    def test_dms_replication_task_logging_enabled_target_load_apply_with_not_enough_severity_on_both(
        self,
    ):
        dms_client = client("dms", region_name=AWS_REGION_US_EAST_1)
        dms_client.create_replication_task(
            ReplicationTaskIdentifier="rep-task",
            SourceEndpointArn=DMS_ENDPOINT_ARN,
            TargetEndpointArn=DMS_ENDPOINT_ARN,
            MigrationType="full-load",
            ReplicationTaskSettings="""
                {
                    "Logging": {
                        "EnableLogging": true,
                        "LogComponents": [
                            {
                                "Id": "TARGET_LOAD",
                                "Severity": "LOGGER_SEVERITY_INFO"
                            },
                            {
                                "Id": "TARGET_APPLY",
                                "Severity": "LOGGER_SEVERITY_INFO"
                            }
                        ]
                    }
                }
            """,
            TableMappings="",
            ReplicationInstanceArn=DMS_INSTANCE_ARN,
        )

        dms_replication_task_arn = dms_client.describe_replication_tasks()[
            "ReplicationTasks"
        ][0]["ReplicationTaskArn"]

        from prowler.providers.aws.services.dms.dms_service import DMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled.dms_client",
            new=DMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled import (
                dms_replication_task_target_logging_enabled,
            )

            check = dms_replication_task_target_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "DMS Replication Task rep-task does not meet the minimum severity level of logging in Target Apply and Target Load events."
            )
            assert result[0].resource_id == "rep-task"
            assert result[0].resource_arn == dms_replication_task_arn
            assert result[0].resource_tags == []
            assert result[0].region == "us-east-1"

    @mock_aws
    def test_dms_replication_task_logging_enabled_target_load_apply_with_enough_severity_on_both(
        self,
    ):
        dms_client = client("dms", region_name=AWS_REGION_US_EAST_1)
        dms_client.create_replication_task(
            ReplicationTaskIdentifier="rep-task",
            SourceEndpointArn=DMS_ENDPOINT_ARN,
            TargetEndpointArn=DMS_ENDPOINT_ARN,
            MigrationType="full-load",
            ReplicationTaskSettings="""
                {
                    "Logging": {
                        "EnableLogging": true,
                        "LogComponents": [
                            {
                                "Id": "TARGET_LOAD",
                                "Severity": "LOGGER_SEVERITY_DEFAULT"
                            },
                            {
                                "Id": "TARGET_APPLY",
                                "Severity": "LOGGER_SEVERITY_DEFAULT"
                            }
                        ]
                    }
                }
            """,
            TableMappings="",
            ReplicationInstanceArn=DMS_INSTANCE_ARN,
        )

        dms_replication_task_arn = dms_client.describe_replication_tasks()[
            "ReplicationTasks"
        ][0]["ReplicationTaskArn"]

        from prowler.providers.aws.services.dms.dms_service import DMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled.dms_client",
            new=DMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dms.dms_replication_task_target_logging_enabled.dms_replication_task_target_logging_enabled import (
                dms_replication_task_target_logging_enabled,
            )

            check = dms_replication_task_target_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "DMS Replication Task rep-task has logging enabled with the minimum severity level in target events."
            )
            assert result[0].resource_id == "rep-task"
            assert result[0].resource_arn == dms_replication_task_arn
            assert result[0].resource_tags == []
            assert result[0].region == "us-east-1"
