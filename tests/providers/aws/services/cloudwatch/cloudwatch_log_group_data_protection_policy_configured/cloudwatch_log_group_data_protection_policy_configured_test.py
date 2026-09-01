from unittest import mock

from prowler.providers.aws.services.cloudwatch.cloudwatch_service import LogGroup
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_PATH = "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured"

log_group_name = "test-log-group"
log_group_arn = (
    f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:{log_group_name}"
)

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


def _log_group(data_protection_policy=None):
    return LogGroup(
        arn=log_group_arn,
        name=log_group_name,
        retention_days=9999,
        never_expire=True,
        kms_id=None,
        region=AWS_REGION_US_EAST_1,
        data_protection_policy=data_protection_policy,
    )


def _run_check(log_groups):
    logs_client = mock.MagicMock
    logs_client.log_groups = log_groups

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_PATH}.logs_client", logs_client),
    ):
        from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_data_protection_policy_configured.cloudwatch_log_group_data_protection_policy_configured import (
            cloudwatch_log_group_data_protection_policy_configured,
        )

        return cloudwatch_log_group_data_protection_policy_configured().execute()


class Test_cloudwatch_log_group_data_protection_policy_configured:
    def test_no_log_groups(self):
        result = _run_check({})
        assert len(result) == 0

    def test_log_group_with_active_policy(self):
        result = _run_check({log_group_arn: _log_group(ACTIVE_POLICY)})

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Log Group {log_group_name} has a data protection policy that audits or "
            "de-identifies sensitive data identifiers."
        )
        assert result[0].resource_id == log_group_name
        assert result[0].resource_arn == log_group_arn
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_log_group_without_policy(self):
        result = _run_check({log_group_arn: _log_group(None)})

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Log Group {log_group_name} does not have a data protection policy "
            "configured to audit or de-identify sensitive data identifiers."
        )

    def test_log_group_policy_without_protective_operations(self):
        # A policy with statements that reference no data identifiers is not effective
        # protection.
        policy = {
            "Name": "empty-policy",
            "Version": "2021-06-01",
            "Statement": [
                {"Sid": "s1", "DataIdentifier": [], "Operation": {"Audit": {}}}
            ],
        }
        result = _run_check({log_group_arn: _log_group(policy)})

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_log_group_audit_only_policy(self):
        policy = {
            "Name": "audit-only",
            "Version": "2021-06-01",
            "Statement": [
                {
                    "Sid": "audit",
                    "DataIdentifier": [EMAIL_IDENTIFIER],
                    "Operation": {"Audit": {"FindingsDestination": {}}},
                }
            ],
        }
        result = _run_check({log_group_arn: _log_group(policy)})

        assert len(result) == 1
        assert result[0].status == "PASS"
