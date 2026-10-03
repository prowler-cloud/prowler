from datetime import datetime, timedelta, timezone
from unittest import mock

from prowler.providers.snowflake.services.users.users_service import User
from tests.providers.snowflake.snowflake_fixtures import set_mocked_snowflake_provider


class TestUsersMfaEnabled:
    def _run(self, users):
        """Execute the check against a stubbed users client.

        Args:
            users: The User instances the client should report.

        Returns:
            list: The findings produced by the check.
        """
        users_client = mock.MagicMock()
        users_client.users = users
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_snowflake_provider(),
            ),
            mock.patch(
                "prowler.providers.snowflake.services.users.users_mfa_enabled.users_mfa_enabled.users_client",
                new=users_client,
            ),
        ):
            from prowler.providers.snowflake.services.users.users_mfa_enabled.users_mfa_enabled import (
                users_mfa_enabled,
            )

            return users_mfa_enabled().execute()

    def test_no_users_no_findings(self):
        assert self._run([]) == []

    def test_password_user_without_mfa_fails(self):
        findings = self._run([User(name="ALICE", has_password=True)])
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert findings[0].resource_id == "ALICE"
        assert findings[0].resource_name == "ALICE"
        assert findings[0].region == "global"
        assert "not enrolled in MFA" in findings[0].status_extended

    def test_password_user_with_native_mfa_passes(self):
        findings = self._run([User(name="ALICE", has_password=True, has_mfa=True)])
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "enrolled in MFA" in findings[0].status_extended

    def test_password_user_with_legacy_duo_passes(self):
        # The regression this check was built around: keying on HAS_MFA alone reports
        # every Duo-enrolled user as unprotected, which is a false high-severity
        # finding per user.
        findings = self._run(
            [User(name="ALICE", has_password=True, ext_authn_duo=True)]
        )
        assert len(findings) == 1
        assert findings[0].status == "PASS"

    def test_enrolled_but_currently_bypassed_fails(self):
        future = datetime.now(timezone.utc) + timedelta(hours=2)
        findings = self._run(
            [
                User(
                    name="ALICE",
                    has_password=True,
                    has_mfa=True,
                    bypass_mfa_until=future,
                )
            ]
        )
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "bypass" in findings[0].status_extended

    def test_enrolled_with_an_expired_bypass_passes(self):
        past = datetime.now(timezone.utc) - timedelta(hours=2)
        findings = self._run(
            [User(name="ALICE", has_password=True, has_mfa=True, bypass_mfa_until=past)]
        )
        assert findings[0].status == "PASS"

    def test_disabled_users_are_not_reported(self):
        # A disabled user cannot sign in, so the absence of MFA exposes nothing.
        assert self._run([User(name="ALICE", has_password=True, disabled=True)]) == []

    def test_users_without_a_password_are_not_reported(self):
        # Key-pair-only users -- the recommended shape for service accounts -- have no
        # password to protect with a second factor.
        assert (
            self._run([User(name="SVC", has_password=False, has_rsa_public_key=True)])
            == []
        )

    def test_each_user_gets_its_own_finding(self):
        findings = self._run(
            [
                User(name="ALICE", has_password=True, has_mfa=True),
                User(name="BOB", has_password=True),
                User(name="SVC", has_password=False),
            ]
        )
        assert len(findings) == 2
        assert {f.resource_id for f in findings} == {"ALICE", "BOB"}
        assert {f.status for f in findings} == {"PASS", "FAIL"}
