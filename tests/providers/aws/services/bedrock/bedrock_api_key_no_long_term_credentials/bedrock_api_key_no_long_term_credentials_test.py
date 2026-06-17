from datetime import datetime, timedelta, timezone
from unittest import mock

from moto import mock_aws

from prowler.lib.check.models import Severity
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

BEDROCK_SERVICE = "bedrock.amazonaws.com"


def _make_user(name="test_user"):
    from prowler.providers.aws.services.iam.iam_service import User

    return User(
        name=name,
        arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/{name}",
        attached_policies=[],
        inline_policies=[],
    )


def _make_credential(
    user,
    credential_id="test-credential-id",
    expiration_delta_days=None,
    service_name=BEDROCK_SERVICE,
):
    from prowler.providers.aws.services.iam.iam_service import ServiceSpecificCredential

    expiration_date = (
        datetime.now(timezone.utc) + timedelta(days=expiration_delta_days)
        if expiration_delta_days is not None
        else None
    )
    return ServiceSpecificCredential(
        arn=(
            f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/{user.name}/"
            f"credential/{credential_id}"
        ),
        user=user,
        status="Active",
        create_date=datetime.now(timezone.utc),
        service_user_name=None,
        service_credential_alias=None,
        expiration_date=expiration_date,
        id=credential_id,
        service_name=service_name,
        region=AWS_REGION_US_EAST_1,
    )


def _run_check(credentials):
    from prowler.providers.aws.services.iam.iam_service import IAM

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    iam = IAM(aws_provider)
    iam.service_specific_credentials = credentials

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials.iam_client",
            new=iam,
        ),
    ):
        from prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials import (
            bedrock_api_key_no_long_term_credentials,
        )

        check = bedrock_api_key_no_long_term_credentials()
        return check.execute()


class Test_bedrock_api_key_no_long_term_credentials:
    @mock_aws
    def test_no_bedrock_api_keys(self):
        assert _run_check([]) == []

    @mock_aws
    def test_active_short_expiration_key_fails_high(self):
        # Per AWS guidance, every active long-term key is a finding regardless of
        # how soon it expires. Short remaining lifetime does not downgrade severity.
        credential = _make_credential(_make_user(), expiration_delta_days=30)
        result = _run_check([credential])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].check_metadata.Severity == Severity.high
        assert "is active and will expire in" in result[0].status_extended
        assert "short-term Bedrock API keys" in result[0].status_extended

    @mock_aws
    def test_active_long_expiration_key_fails_high(self):
        credential = _make_credential(_make_user(), expiration_delta_days=365)
        result = _run_check([credential])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].check_metadata.Severity == Severity.high
        assert "is active and will expire in" in result[0].status_extended

    @mock_aws
    def test_never_expires_key_fails_critical(self):
        # >10000 days approximates AWS's "no expiration" sentinel (~100 years).
        credential = _make_credential(_make_user(), expiration_delta_days=15000)
        result = _run_check([credential])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].check_metadata.Severity == Severity.critical
        assert "configured to never expire" in result[0].status_extended
        assert "short-term Bedrock API keys" in result[0].status_extended

    @mock_aws
    def test_already_expired_key_passes(self):
        credential = _make_credential(_make_user(), expiration_delta_days=-30)
        result = _run_check([credential])

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "has already expired" in result[0].status_extended

    @mock_aws
    def test_key_without_expiration_date_ignored(self):
        credential = _make_credential(_make_user(), expiration_delta_days=None)
        assert _run_check([credential]) == []

    @mock_aws
    def test_non_bedrock_service_ignored(self):
        credential = _make_credential(
            _make_user(),
            expiration_delta_days=30,
            service_name="codecommit.amazonaws.com",
        )
        assert _run_check([credential]) == []

    @mock_aws
    def test_mixed_scenarios(self):
        user1, user2, user3 = (
            _make_user("u1"),
            _make_user("u2"),
            _make_user("u3"),
        )
        credentials = [
            _make_credential(user1, "active-key", expiration_delta_days=191),
            _make_credential(user2, "never-key", expiration_delta_days=15000),
            _make_credential(user3, "expired-key", expiration_delta_days=-30),
        ]
        result = _run_check(credentials)

        assert len(result) == 3
        by_id = {r.resource_id: r for r in result}

        assert by_id["active-key"].status == "FAIL"
        assert by_id["active-key"].check_metadata.Severity == Severity.high

        assert by_id["never-key"].status == "FAIL"
        assert by_id["never-key"].check_metadata.Severity == Severity.critical

        assert by_id["expired-key"].status == "PASS"

    @mock_aws
    def test_severity_does_not_leak_never_then_active(self):
        """Regression: a never-expires key processed before an active key must
        not bleed `critical` severity into the active finding."""
        credentials = [
            _make_credential(
                _make_user("u-never"), "never-key", expiration_delta_days=15000
            ),
            _make_credential(
                _make_user("u-active"), "active-key", expiration_delta_days=191
            ),
        ]
        result = _run_check(credentials)

        by_id = {r.resource_id: r for r in result}
        assert by_id["never-key"].check_metadata.Severity == Severity.critical
        assert by_id["active-key"].check_metadata.Severity == Severity.high

    @mock_aws
    def test_severity_does_not_leak_active_then_never(self):
        """Regression: same as above with the reverse iteration order."""
        credentials = [
            _make_credential(
                _make_user("u-active"), "active-key", expiration_delta_days=191
            ),
            _make_credential(
                _make_user("u-never"), "never-key", expiration_delta_days=15000
            ),
        ]
        result = _run_check(credentials)

        by_id = {r.resource_id: r for r in result}
        assert by_id["active-key"].check_metadata.Severity == Severity.high
        assert by_id["never-key"].check_metadata.Severity == Severity.critical
