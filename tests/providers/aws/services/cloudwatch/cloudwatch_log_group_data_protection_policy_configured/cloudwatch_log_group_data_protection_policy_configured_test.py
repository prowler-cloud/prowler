from unittest import mock

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_PATH = "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured"

log_group_name = "test-log-group"
log_group_arn = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:{log_group_name}"

EMAIL_IDENTIFIER = "arn:aws:dataprotection::aws:data-identifier/EmailAddress"

ACTIVE_POLICY = {
    "Name": "data-protection-policy",
    "Version": "2021-06-01",
    "Statement": [
        {
            "Sid": "audit",
            "DataIdentifier": [EMAIL_IDENTIFIER],
            "Operation": {"Audit": {"FindingsDestination": {}}},
        },
        {
            "Sid": "redact",
            "DataIdentifier": [EMAIL_IDENTIFIER],
            "Operation": {"Deidentify": {"MaskConfig": {}}},
        },
    ],
}


def _run_check(log_groups):
    logs_client = mock.MagicMock()
    logs_client.log_groups = log_groups
    logs_client.region = AWS_REGION_US_EAST_1
    logs_client.audited_account = AWS_ACCOUNT_NUMBER
    logs_client.log_group_arn_template = (
        f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group"
    )

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_PATH}.logs_client", new=logs_client),
    ):
        from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured import (
            cloudwatch_log_group_data_protection_policy_configured,
        )

        return cloudwatch_log_group_data_protection_policy_configured().execute()


class Test_cloudwatch_log_group_data_protection_policy_configured:
    def test_no_log_groups(self):
        result = _run_check({})
        assert len(result) == 0

    def test_log_groups_unavailable(self):
        result = _run_check(None)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == "Log groups could not be retrieved, so data protection policies for CloudWatch log groups could not be verified."
        )
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER
        assert (
            result[0].resource_arn
            == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group"
        )
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_log_group_with_active_data_protection_policy(self):
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            LogGroup,
        )

        log_groups = {
            log_group_arn: LogGroup(
                arn=log_group_arn,
                name=log_group_name,
                retention_days=365,
                never_expire=False,
                kms_id=None,
                region=AWS_REGION_US_EAST_1,
                data_protection_status="ACTIVATED",
                inherited_properties=[],
                data_protection_policy=ACTIVE_POLICY,
                data_protection_policy_retrieved=True,
            )
        }

        result = _run_check(log_groups)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Log Group {log_group_name} has a data protection policy configured to audit or de-identify sensitive data identifiers."
        )
        assert result[0].resource_id == log_group_name
        assert result[0].resource_arn == log_group_arn
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_log_group_with_inherited_data_protection_policy(self):
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            LogGroup,
        )

        log_groups = {
            log_group_arn: LogGroup(
                arn=log_group_arn,
                name=log_group_name,
                retention_days=365,
                never_expire=False,
                kms_id=None,
                region=AWS_REGION_US_EAST_1,
                data_protection_status=None,
                inherited_properties=["ACCOUNT_DATA_PROTECTION"],
                data_protection_policy=None,
                data_protection_policy_retrieved=False,
            )
        }

        result = _run_check(log_groups)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Log Group {log_group_name} has a data protection policy configured via account-level inheritance."
        )
        assert result[0].resource_id == log_group_name
        assert result[0].resource_arn == log_group_arn
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_log_group_with_inactive_data_protection_policy(self):
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            LogGroup,
        )

        log_groups = {
            log_group_arn: LogGroup(
                arn=log_group_arn,
                name=log_group_name,
                retention_days=365,
                never_expire=False,
                kms_id=None,
                region=AWS_REGION_US_EAST_1,
                data_protection_status="DISABLED",
                inherited_properties=[],
                data_protection_policy=ACTIVE_POLICY,
                data_protection_policy_retrieved=True,
            )
        }

        result = _run_check(log_groups)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Log Group {log_group_name} does not have an active data protection policy configured."
        )
        assert result[0].resource_id == log_group_name
        assert result[0].resource_arn == log_group_arn
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_log_group_without_data_protection_policy(self):
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            LogGroup,
        )

        log_groups = {
            log_group_arn: LogGroup(
                arn=log_group_arn,
                name=log_group_name,
                retention_days=365,
                never_expire=False,
                kms_id=None,
                region=AWS_REGION_US_EAST_1,
                data_protection_status=None,
                inherited_properties=[],
                data_protection_policy=None,
                data_protection_policy_retrieved=True,
            )
        }

        result = _run_check(log_groups)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Log Group {log_group_name} does not have an active data protection policy configured."
        )
        assert result[0].resource_id == log_group_name
        assert result[0].resource_arn == log_group_arn
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_log_group_policy_without_protective_operations(self):
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            LogGroup,
        )

        empty_policy = {
            "Name": "empty-policy",
            "Version": "2021-06-01",
            "Statement": [
                {"Sid": "s1", "DataIdentifier": [], "Operation": {"Audit": {}}}
            ],
        }

        log_groups = {
            log_group_arn: LogGroup(
                arn=log_group_arn,
                name=log_group_name,
                retention_days=365,
                never_expire=False,
                kms_id=None,
                region=AWS_REGION_US_EAST_1,
                data_protection_status="ACTIVATED",
                inherited_properties=[],
                data_protection_policy=empty_policy,
                data_protection_policy_retrieved=True,
            )
        }

        result = _run_check(log_groups)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Log Group {log_group_name} does not have an active data protection policy configured."
        )

    def test_log_group_data_protection_policy_unretrieved(self):
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            LogGroup,
        )

        log_groups = {
            log_group_arn: LogGroup(
                arn=log_group_arn,
                name=log_group_name,
                retention_days=365,
                never_expire=False,
                kms_id=None,
                region=AWS_REGION_US_EAST_1,
                data_protection_status=None,
                inherited_properties=[],
                data_protection_policy=None,
                data_protection_policy_retrieved=False,
            )
        }

        result = _run_check(log_groups)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Log Group {log_group_name} data protection policy could not be retrieved in region {AWS_REGION_US_EAST_1}; verify manually."
        )
        assert result[0].resource_id == log_group_name
        assert result[0].resource_arn == log_group_arn
        assert result[0].region == AWS_REGION_US_EAST_1
