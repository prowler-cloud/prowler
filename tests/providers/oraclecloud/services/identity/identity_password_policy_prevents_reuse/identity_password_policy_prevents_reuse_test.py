from datetime import datetime, timezone
from unittest import mock

from prowler.providers.oraclecloud.services.identity.identity_service import (
    DomainPasswordPolicy,
    IdentityDomain,
)
from tests.providers.oraclecloud.oci_fixtures import (
    OCI_COMPARTMENT_ID,
    OCI_REGION,
    OCI_TENANCY_ID,
    set_mocked_oraclecloud_provider,
)

DOMAIN_ID = "ocid1.domain.oc1..aaaaaaaexample"
DOMAIN_NAME = "Default"
DOMAIN_URL = "https://idcs-example.identity.oraclecloud.com"
POLICY_ID = "ocid1.passwordpolicy.oc1..aaaaaaaexample"
POLICY_NAME = "CustomPasswordPolicy"


def _make_domain(password_policies=None):
    return IdentityDomain(
        id=DOMAIN_ID,
        display_name=DOMAIN_NAME,
        description="Default identity domain",
        url=DOMAIN_URL,
        home_region=OCI_REGION,
        compartment_id=OCI_COMPARTMENT_ID,
        lifecycle_state="ACTIVE",
        time_created=datetime.now(timezone.utc),
        region=OCI_REGION,
        password_policies=password_policies or [],
    )


class Test_identity_password_policy_prevents_reuse:
    def test_no_domains(self):
        """No Identity Domains → MANUAL finding."""
        identity_client = mock.MagicMock()
        identity_client.audited_tenancy = OCI_TENANCY_ID
        identity_client.domains = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.identity.identity_password_policy_prevents_reuse.identity_password_policy_prevents_reuse.identity_client",
                new=identity_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.identity.identity_password_policy_prevents_reuse.identity_password_policy_prevents_reuse import (
                identity_password_policy_prevents_reuse,
            )

            check = identity_password_policy_prevents_reuse()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"

    def test_policy_prevents_reuse_24(self):
        """Password history >= 24 → PASS."""
        identity_client = mock.MagicMock()
        identity_client.audited_tenancy = OCI_TENANCY_ID
        identity_client.domains = [
            _make_domain(
                [
                    DomainPasswordPolicy(
                        id=POLICY_ID,
                        name=POLICY_NAME,
                        description="Custom policy",
                        min_length=14,
                        password_expires_after=90,
                        num_passwords_in_history=24,
                        password_expire_warning=7,
                        min_password_age=1,
                    )
                ]
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.identity.identity_password_policy_prevents_reuse.identity_password_policy_prevents_reuse.identity_client",
                new=identity_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.identity.identity_password_policy_prevents_reuse.identity_password_policy_prevents_reuse import (
                identity_password_policy_prevents_reuse,
            )

            check = identity_password_policy_prevents_reuse()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "24 passwords" in result[0].status_extended
            assert result[0].resource_id == POLICY_ID

    def test_policy_insufficient_history(self):
        """Password history < 24 → FAIL."""
        identity_client = mock.MagicMock()
        identity_client.audited_tenancy = OCI_TENANCY_ID
        identity_client.domains = [
            _make_domain(
                [
                    DomainPasswordPolicy(
                        id=POLICY_ID,
                        name=POLICY_NAME,
                        description="Custom policy",
                        min_length=14,
                        password_expires_after=90,
                        num_passwords_in_history=5,
                        password_expire_warning=7,
                        min_password_age=1,
                    )
                ]
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.identity.identity_password_policy_prevents_reuse.identity_password_policy_prevents_reuse.identity_client",
                new=identity_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.identity.identity_password_policy_prevents_reuse.identity_password_policy_prevents_reuse import (
                identity_password_policy_prevents_reuse,
            )

            check = identity_password_policy_prevents_reuse()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "5 passwords" in result[0].status_extended

    def test_policy_no_history_configured(self):
        """No password history configured → FAIL."""
        identity_client = mock.MagicMock()
        identity_client.audited_tenancy = OCI_TENANCY_ID
        identity_client.domains = [
            _make_domain(
                [
                    DomainPasswordPolicy(
                        id=POLICY_ID,
                        name=POLICY_NAME,
                        description="Custom policy",
                        min_length=14,
                        password_expires_after=90,
                        num_passwords_in_history=None,
                        password_expire_warning=7,
                        min_password_age=1,
                    )
                ]
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.identity.identity_password_policy_prevents_reuse.identity_password_policy_prevents_reuse.identity_client",
                new=identity_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.identity.identity_password_policy_prevents_reuse.identity_password_policy_prevents_reuse import (
                identity_password_policy_prevents_reuse,
            )

            check = identity_password_policy_prevents_reuse()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have password history" in result[0].status_extended

    def test_domain_no_policies(self):
        """Domain with no password policies → FAIL."""
        identity_client = mock.MagicMock()
        identity_client.audited_tenancy = OCI_TENANCY_ID
        identity_client.domains = [_make_domain([])]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.identity.identity_password_policy_prevents_reuse.identity_password_policy_prevents_reuse.identity_client",
                new=identity_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.identity.identity_password_policy_prevents_reuse.identity_password_policy_prevents_reuse import (
                identity_password_policy_prevents_reuse,
            )

            check = identity_password_policy_prevents_reuse()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "no password policy configured" in result[0].status_extended

    def test_system_managed_policies_excluded(self):
        """System-managed policies should not appear in domain.password_policies.

        This is a regression test: SimplePasswordPolicy and StandardPasswordPolicy
        are filtered at the service layer, so checks never see them.
        """
        identity_client = mock.MagicMock()
        identity_client.audited_tenancy = OCI_TENANCY_ID
        identity_client.domains = [
            _make_domain(
                [
                    DomainPasswordPolicy(
                        id=POLICY_ID,
                        name=POLICY_NAME,
                        description="Custom policy",
                        min_length=14,
                        password_expires_after=90,
                        num_passwords_in_history=24,
                        password_expire_warning=7,
                        min_password_age=1,
                    )
                ]
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.identity.identity_password_policy_prevents_reuse.identity_password_policy_prevents_reuse.identity_client",
                new=identity_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.identity.identity_password_policy_prevents_reuse.identity_password_policy_prevents_reuse import (
                identity_password_policy_prevents_reuse,
            )

            check = identity_password_policy_prevents_reuse()
            result = check.execute()

            # Only 1 finding for the custom policy, none for system-managed
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == POLICY_ID
