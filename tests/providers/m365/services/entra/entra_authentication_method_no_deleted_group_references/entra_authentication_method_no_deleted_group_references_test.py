from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    AuthenticationMethodConfiguration,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


def _make_config(
    *,
    method_id="MicrosoftAuthenticator",
    state="enabled",
    include_target_group_ids=None,
    exclude_target_group_ids=None,
    targets_read=True,
):
    """Build an AuthenticationMethodConfiguration with the given parameters."""
    return AuthenticationMethodConfiguration(
        id=method_id,
        state=state,
        include_target_group_ids=include_target_group_ids or [],
        exclude_target_group_ids=exclude_target_group_ids or [],
        targets_read=targets_read,
    )


def _entra_client_mock():
    client = mock.MagicMock()
    client.audited_tenant = "audited_tenant"
    client.audited_domain = DOMAIN
    client.tenant_domain = DOMAIN
    client.authentication_method_configurations = {}
    client.unresolved_authentication_method_group_references = set()
    client.errored_authentication_method_group_references = set()
    client.authentication_method_configurations_error = None
    return client


CHECK_MODULE = (
    "prowler.providers.m365.services.entra."
    "entra_authentication_method_no_deleted_group_references."
    "entra_authentication_method_no_deleted_group_references.entra_client"
)


class Test_entra_authentication_method_no_deleted_group_references:
    def test_no_configurations(self):
        """No authentication method configurations (no error): no findings."""
        entra_client = _entra_client_mock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_no_deleted_group_references.entra_authentication_method_no_deleted_group_references import (
                entra_authentication_method_no_deleted_group_references,
            )

            check = entra_authentication_method_no_deleted_group_references()
            result = check.execute()

            assert len(result) == 0

    def test_policy_read_error_manual(self):
        """Policy could not be read: emit one tenant-level MANUAL finding."""
        entra_client = _entra_client_mock()
        entra_client.authentication_method_configurations = {}
        entra_client.authentication_method_configurations_error = "403 Forbidden"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_no_deleted_group_references.entra_authentication_method_no_deleted_group_references import (
                entra_authentication_method_no_deleted_group_references,
            )

            check = entra_authentication_method_no_deleted_group_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_id == "authenticationMethodsPolicy"
            assert result[0].resource_name == "Authentication Methods Policy"
            assert "could not be read" in result[0].status_extended

    def test_all_users_only_pass(self):
        """Config targeting all_users (no group ids) passes."""
        entra_client = _entra_client_mock()
        config = _make_config(method_id="Fido2", state="enabled")
        entra_client.authentication_method_configurations = {"Fido2": config}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_no_deleted_group_references.entra_authentication_method_no_deleted_group_references import (
                entra_authentication_method_no_deleted_group_references,
            )

            check = entra_authentication_method_no_deleted_group_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "Fido2"
            assert "does not reference deleted groups" in result[0].status_extended

    def test_all_references_resolve_pass(self):
        """Config with group ids that all resolve: PASS."""
        entra_client = _entra_client_mock()
        live_group = str(uuid4())
        config = _make_config(
            method_id="MicrosoftAuthenticator",
            include_target_group_ids=[live_group],
        )
        entra_client.authentication_method_configurations = {
            "MicrosoftAuthenticator": config
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_no_deleted_group_references.entra_authentication_method_no_deleted_group_references import (
                entra_authentication_method_no_deleted_group_references,
            )

            check = entra_authentication_method_no_deleted_group_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_deleted_include_group_fails(self):
        """Config with a deleted group in includeTargets: FAIL."""
        entra_client = _entra_client_mock()
        deleted_group = str(uuid4())
        config = _make_config(
            method_id="Fido2",
            state="enabled",
            include_target_group_ids=[deleted_group],
        )
        entra_client.authentication_method_configurations = {"Fido2": config}
        entra_client.unresolved_authentication_method_group_references = {deleted_group}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_no_deleted_group_references.entra_authentication_method_no_deleted_group_references import (
                entra_authentication_method_no_deleted_group_references,
            )

            check = entra_authentication_method_no_deleted_group_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "include" in result[0].status_extended
            assert deleted_group in result[0].status_extended
            assert "Fido2" in result[0].status_extended

    def test_deleted_exclude_group_fails(self):
        """Config with a deleted group in excludeTargets: FAIL."""
        entra_client = _entra_client_mock()
        deleted_group = str(uuid4())
        config = _make_config(
            method_id="Sms",
            state="enabled",
            exclude_target_group_ids=[deleted_group],
        )
        entra_client.authentication_method_configurations = {"Sms": config}
        entra_client.unresolved_authentication_method_group_references = {deleted_group}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_no_deleted_group_references.entra_authentication_method_no_deleted_group_references import (
                entra_authentication_method_no_deleted_group_references,
            )

            check = entra_authentication_method_no_deleted_group_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "exclude" in result[0].status_extended
            assert deleted_group in result[0].status_extended

    def test_disabled_method_still_fails(self):
        """Disabled method with a deleted group: still FAIL."""
        entra_client = _entra_client_mock()
        deleted_group = str(uuid4())
        config = _make_config(
            method_id="TemporaryAccessPass",
            state="disabled",
            include_target_group_ids=[deleted_group],
        )
        entra_client.authentication_method_configurations = {
            "TemporaryAccessPass": config
        }
        entra_client.unresolved_authentication_method_group_references = {deleted_group}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_no_deleted_group_references.entra_authentication_method_no_deleted_group_references import (
                entra_authentication_method_no_deleted_group_references,
            )

            check = entra_authentication_method_no_deleted_group_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "disabled" in result[0].status_extended

    def test_errored_reference_manual(self):
        """Config with an errored (non-404) group reference: MANUAL."""
        entra_client = _entra_client_mock()
        errored_group = str(uuid4())
        config = _make_config(
            method_id="Fido2",
            state="enabled",
            include_target_group_ids=[errored_group],
        )
        entra_client.authentication_method_configurations = {"Fido2": config}
        entra_client.errored_authentication_method_group_references = {errored_group}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_no_deleted_group_references.entra_authentication_method_no_deleted_group_references import (
                entra_authentication_method_no_deleted_group_references,
            )

            check = entra_authentication_method_no_deleted_group_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "could not be fully evaluated" in result[0].status_extended

    def test_deleted_takes_precedence_over_errored(self):
        """FAIL takes precedence over MANUAL when both deleted and errored refs exist."""
        entra_client = _entra_client_mock()
        deleted_group = str(uuid4())
        errored_group = str(uuid4())
        config = _make_config(
            method_id="Fido2",
            state="enabled",
            include_target_group_ids=[deleted_group],
            exclude_target_group_ids=[errored_group],
        )
        entra_client.authentication_method_configurations = {"Fido2": config}
        entra_client.unresolved_authentication_method_group_references = {deleted_group}
        entra_client.errored_authentication_method_group_references = {errored_group}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_no_deleted_group_references.entra_authentication_method_no_deleted_group_references import (
                entra_authentication_method_no_deleted_group_references,
            )

            check = entra_authentication_method_no_deleted_group_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "could not be verified" in result[0].status_extended

    def test_targets_not_read_manual(self):
        """Config with targets_read=False: MANUAL."""
        entra_client = _entra_client_mock()
        config = _make_config(
            method_id="X509Certificate",
            state="enabled",
            targets_read=False,
        )
        entra_client.authentication_method_configurations = {"X509Certificate": config}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_no_deleted_group_references.entra_authentication_method_no_deleted_group_references import (
                entra_authentication_method_no_deleted_group_references,
            )

            check = entra_authentication_method_no_deleted_group_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "could not be read" in result[0].status_extended

    def test_multiple_configs_mixed(self):
        """Multiple configs: clean one PASSes, dirty one FAILs."""
        entra_client = _entra_client_mock()
        deleted_group = str(uuid4())

        clean_config = _make_config(method_id="Fido2", state="enabled")
        dirty_config = _make_config(
            method_id="Sms",
            state="enabled",
            include_target_group_ids=[deleted_group],
        )
        entra_client.authentication_method_configurations = {
            "Fido2": clean_config,
            "Sms": dirty_config,
        }
        entra_client.unresolved_authentication_method_group_references = {deleted_group}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_no_deleted_group_references.entra_authentication_method_no_deleted_group_references import (
                entra_authentication_method_no_deleted_group_references,
            )

            check = entra_authentication_method_no_deleted_group_references()
            result = check.execute()

            assert len(result) == 2

            fido2_result = next(r for r in result if r.resource_id == "Fido2")
            sms_result = next(r for r in result if r.resource_id == "Sms")

            assert fido2_result.status == "PASS"
            assert sms_result.status == "FAIL"

    def test_both_include_and_exclude_deleted(self):
        """Config with deleted groups in both include and exclude: FAIL lists both."""
        entra_client = _entra_client_mock()
        deleted_include = str(uuid4())
        deleted_exclude = str(uuid4())
        config = _make_config(
            method_id="MicrosoftAuthenticator",
            state="enabled",
            include_target_group_ids=[deleted_include],
            exclude_target_group_ids=[deleted_exclude],
        )
        entra_client.authentication_method_configurations = {
            "MicrosoftAuthenticator": config
        }
        entra_client.unresolved_authentication_method_group_references = {
            deleted_include,
            deleted_exclude,
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_no_deleted_group_references.entra_authentication_method_no_deleted_group_references import (
                entra_authentication_method_no_deleted_group_references,
            )

            check = entra_authentication_method_no_deleted_group_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "include" in result[0].status_extended
            assert "exclude" in result[0].status_extended
            assert deleted_include in result[0].status_extended
            assert deleted_exclude in result[0].status_extended
