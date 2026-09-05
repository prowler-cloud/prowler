from unittest import mock

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_cloudwatch_log_group_data_protection_policy_configured:
    def test_cloudwatch_no_log_groups(self):
        logs_client = mock.MagicMock()
        logs_client.log_groups = {}

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured.logs_client",
                new=logs_client,
            ),
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured import (
                cloudwatch_log_group_data_protection_policy_configured,
            )

            check = cloudwatch_log_group_data_protection_policy_configured()
            result = check.execute()

            assert len(result) == 0

    def test_cloudwatch_log_group_without_data_protection_policy(self):
        logs_client = mock.MagicMock()
        logs_client.log_groups = {}

        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            LogGroup,
        )

        log_group_name = "test-log-group"
        log_group_arn = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:{log_group_name}"

        logs_client.log_groups[log_group_arn] = LogGroup(
            arn=log_group_arn,
            name=log_group_name,
            retention_days=365,
            never_expire=False,
            kms_id=None,
            region=AWS_REGION_US_EAST_1,
            data_protection_policy=None,
            data_protection_policy_retrieved=True,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured.logs_client",
                new=logs_client,
            ),
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured import (
                cloudwatch_log_group_data_protection_policy_configured,
            )

            check = cloudwatch_log_group_data_protection_policy_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Log Group {log_group_name} does not have an active data protection policy configured."
            )
            assert result[0].resource_id == log_group_name
            assert result[0].resource_arn == log_group_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_cloudwatch_log_group_with_data_protection_policy(self):
        logs_client = mock.MagicMock()
        logs_client.log_groups = {}

        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            LogGroup,
        )

        log_group_name = "test-log-group"
        log_group_arn = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:{log_group_name}"

        logs_client.log_groups[log_group_arn] = LogGroup(
            arn=log_group_arn,
            name=log_group_name,
            retention_days=365,
            never_expire=False,
            kms_id=None,
            region=AWS_REGION_US_EAST_1,
            data_protection_policy={
                "Statement": [
                    {
                        "DataIdentifier": [
                            "arn:aws:dataprotection::aws:data-identifier/Credentials"
                        ],
                        "Operation": {"Audit": {"FindingsDestination": {}}},
                    }
                ]
            },
            data_protection_policy_retrieved=True,
            data_protection_status="ACTIVATED",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured.logs_client",
                new=logs_client,
            ),
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured import (
                cloudwatch_log_group_data_protection_policy_configured,
            )

            check = cloudwatch_log_group_data_protection_policy_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Log Group {log_group_name} has a data protection policy configured."
            )
            assert result[0].resource_id == log_group_name
            assert result[0].resource_arn == log_group_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_cloudwatch_log_group_policy_not_retrieved(self):
        logs_client = mock.MagicMock()
        logs_client.log_groups = {}

        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            LogGroup,
        )

        log_group_name = "access-denied-group"
        log_group_arn = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:{log_group_name}"

        logs_client.log_groups[log_group_arn] = LogGroup(
            arn=log_group_arn,
            name=log_group_name,
            retention_days=365,
            never_expire=False,
            kms_id=None,
            region=AWS_REGION_US_EAST_1,
            data_protection_policy=None,
            data_protection_policy_retrieved=False,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured.logs_client",
                new=logs_client,
            ),
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured import (
                cloudwatch_log_group_data_protection_policy_configured,
            )

            check = cloudwatch_log_group_data_protection_policy_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"Log Group {log_group_name} data protection policy could not be retrieved in region {AWS_REGION_US_EAST_1}; verify manually."
            )
            assert result[0].resource_id == log_group_name
            assert result[0].resource_arn == log_group_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_cloudwatch_log_group_with_inactive_data_protection_policy(self):
        logs_client = mock.MagicMock()
        logs_client.log_groups = {}

        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            LogGroup,
        )

        log_group_name = "test-log-group-inactive"
        log_group_arn = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:{log_group_name}"

        logs_client.log_groups[log_group_arn] = LogGroup(
            arn=log_group_arn,
            name=log_group_name,
            retention_days=365,
            never_expire=False,
            kms_id=None,
            region=AWS_REGION_US_EAST_1,
            data_protection_policy={
                "Statement": [
                    {
                        "DataIdentifier": [
                            "arn:aws:dataprotection::aws:data-identifier/Credentials"
                        ],
                        "Operation": {"Audit": {"FindingsDestination": {}}},
                    }
                ]
            },
            data_protection_policy_retrieved=True,
            data_protection_status="DISABLED",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured.logs_client",
                new=logs_client,
            ),
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured import (
                cloudwatch_log_group_data_protection_policy_configured,
            )

            check = cloudwatch_log_group_data_protection_policy_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Log Group {log_group_name} does not have an active data protection policy configured."
            )
            assert result[0].resource_id == log_group_name
            assert result[0].resource_arn == log_group_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_cloudwatch_log_group_with_inherited_data_protection_policy(self):
        logs_client = mock.MagicMock()
        logs_client.log_groups = {}

        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            LogGroup,
        )

        log_group_name = "test-log-group-inherited"
        log_group_arn = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:{log_group_name}"

        logs_client.log_groups[log_group_arn] = LogGroup(
            arn=log_group_arn,
            name=log_group_name,
            retention_days=365,
            never_expire=False,
            kms_id=None,
            region=AWS_REGION_US_EAST_1,
            data_protection_policy=None,
            data_protection_policy_retrieved=False,
            data_protection_status=None,
            inherited_properties=["ACCOUNT_DATA_PROTECTION"],
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured.logs_client",
                new=logs_client,
            ),
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured import (
                cloudwatch_log_group_data_protection_policy_configured,
            )

            check = cloudwatch_log_group_data_protection_policy_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Log Group {log_group_name} has a data protection policy configured."
            )
            assert result[0].resource_id == log_group_name
            assert result[0].resource_arn == log_group_arn
            assert result[0].region == AWS_REGION_US_EAST_1
