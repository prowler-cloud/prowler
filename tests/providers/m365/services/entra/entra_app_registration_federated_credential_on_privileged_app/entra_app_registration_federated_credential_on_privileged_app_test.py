from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    AppRegistration,
    FederatedIdentityCredential,
    ServicePrincipal,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

# Global Administrator (a Control Plane / Tier 0 directory role).
TIER0_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"
CHECK_PATH = (
    "prowler.providers.m365.services.entra."
    "entra_app_registration_federated_credential_on_privileged_app."
    "entra_app_registration_federated_credential_on_privileged_app.entra_client"
)


def _fic(name="github-actions"):
    return FederatedIdentityCredential(
        name=name,
        issuer="https://token.actions.githubusercontent.com",
        subject="repo:acme/deploy:ref:refs/heads/main",
        audiences=["api://AzureADTokenExchange"],
    )


class Test_entra_app_registration_federated_credential_on_privileged_app:
    def test_no_app_registrations(self):
        """No app registrations in tenant: no findings."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_PATH, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_federated_credential_on_privileged_app.entra_app_registration_federated_credential_on_privileged_app import (
                entra_app_registration_federated_credential_on_privileged_app,
            )

            entra_client.app_registrations = {}
            entra_client.service_principals = {}

            check = entra_app_registration_federated_credential_on_privileged_app()
            result = check.execute()

            assert len(result) == 0

    def test_app_no_federated_credentials(self):
        """Privileged app without federated credentials: expected PASS."""
        object_id = str(uuid4())
        app_id = str(uuid4())
        app_name = "Clean Privileged App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_PATH, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_federated_credential_on_privileged_app.entra_app_registration_federated_credential_on_privileged_app import (
                entra_app_registration_federated_credential_on_privileged_app,
            )

            entra_client.app_registrations = {
                object_id: AppRegistration(
                    id=object_id,
                    app_id=app_id,
                    name=app_name,
                    federated_identity_credentials=[],
                )
            }
            entra_client.service_principals = {
                "sp-1": ServicePrincipal(
                    id="sp-1",
                    name=app_name,
                    app_id=app_id,
                    directory_role_template_ids=[TIER0_ROLE_ID],
                )
            }

            check = entra_app_registration_federated_credential_on_privileged_app()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"App registration {app_name} has no federated identity credentials."
            )
            assert result[0].resource_name == app_name
            assert result[0].resource_id == object_id

    def test_federated_credential_but_not_privileged(self):
        """Federated credential on a non-privileged app: expected PASS."""
        object_id = str(uuid4())
        app_id = str(uuid4())
        app_name = "Non Privileged App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_PATH, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_federated_credential_on_privileged_app.entra_app_registration_federated_credential_on_privileged_app import (
                entra_app_registration_federated_credential_on_privileged_app,
            )

            entra_client.app_registrations = {
                object_id: AppRegistration(
                    id=object_id,
                    app_id=app_id,
                    name=app_name,
                    federated_identity_credentials=[_fic()],
                )
            }
            # Service principal exists but holds no Tier 0 role.
            entra_client.service_principals = {
                "sp-1": ServicePrincipal(
                    id="sp-1",
                    name=app_name,
                    app_id=app_id,
                    directory_role_template_ids=[],
                )
            }

            check = entra_app_registration_federated_credential_on_privileged_app()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "no privileged (Tier 0) directory role" in result[0].status_extended
            assert result[0].resource_id == object_id

    def test_federated_credential_on_privileged_app(self):
        """Federated credential on a Tier 0 app: expected FAIL."""
        object_id = str(uuid4())
        app_id = str(uuid4())
        app_name = "Privileged Deploy App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_PATH, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_federated_credential_on_privileged_app.entra_app_registration_federated_credential_on_privileged_app import (
                entra_app_registration_federated_credential_on_privileged_app,
            )

            entra_client.app_registrations = {
                object_id: AppRegistration(
                    id=object_id,
                    app_id=app_id,
                    name=app_name,
                    federated_identity_credentials=[_fic("gh-main")],
                )
            }
            entra_client.service_principals = {
                "sp-1": ServicePrincipal(
                    id="sp-1",
                    name=app_name,
                    app_id=app_id,
                    directory_role_template_ids=[TIER0_ROLE_ID],
                )
            }

            check = entra_app_registration_federated_credential_on_privileged_app()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "1 federated identity credential(s)" in result[0].status_extended
            assert "gh-main" in result[0].status_extended
            assert "token.actions.githubusercontent.com" in result[0].status_extended
            assert result[0].resource_name == app_name
            assert result[0].resource_id == object_id

    def test_multiple_federated_credentials_on_privileged_app(self):
        """Several federated credentials on a Tier 0 app: FAIL with count."""
        object_id = str(uuid4())
        app_id = str(uuid4())
        app_name = "Multi FIC App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_PATH, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_federated_credential_on_privileged_app.entra_app_registration_federated_credential_on_privileged_app import (
                entra_app_registration_federated_credential_on_privileged_app,
            )

            entra_client.app_registrations = {
                object_id: AppRegistration(
                    id=object_id,
                    app_id=app_id,
                    name=app_name,
                    federated_identity_credentials=[
                        _fic(f"cred-{i}") for i in range(7)
                    ],
                )
            }
            entra_client.service_principals = {
                "sp-1": ServicePrincipal(
                    id="sp-1",
                    name=app_name,
                    app_id=app_id,
                    directory_role_template_ids=[TIER0_ROLE_ID],
                )
            }

            check = entra_app_registration_federated_credential_on_privileged_app()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "7 federated identity credential(s)" in result[0].status_extended
            assert "(and 2 more)" in result[0].status_extended

    def test_multiple_apps_mixed(self):
        """Two apps: one privileged with a FIC (FAIL), one clean (PASS)."""
        object_id_fail = str(uuid4())
        app_id_fail = str(uuid4())
        object_id_pass = str(uuid4())
        app_id_pass = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_PATH, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_federated_credential_on_privileged_app.entra_app_registration_federated_credential_on_privileged_app import (
                entra_app_registration_federated_credential_on_privileged_app,
            )

            entra_client.app_registrations = {
                object_id_fail: AppRegistration(
                    id=object_id_fail,
                    app_id=app_id_fail,
                    name="Privileged With FIC",
                    federated_identity_credentials=[_fic()],
                ),
                object_id_pass: AppRegistration(
                    id=object_id_pass,
                    app_id=app_id_pass,
                    name="Privileged Without FIC",
                    federated_identity_credentials=[],
                ),
            }
            entra_client.service_principals = {
                "sp-fail": ServicePrincipal(
                    id="sp-fail",
                    name="Privileged With FIC",
                    app_id=app_id_fail,
                    directory_role_template_ids=[TIER0_ROLE_ID],
                ),
                "sp-pass": ServicePrincipal(
                    id="sp-pass",
                    name="Privileged Without FIC",
                    app_id=app_id_pass,
                    directory_role_template_ids=[TIER0_ROLE_ID],
                ),
            }

            check = entra_app_registration_federated_credential_on_privileged_app()
            result = check.execute()

            assert len(result) == 2
            result_fail = next(r for r in result if r.resource_id == object_id_fail)
            result_pass = next(r for r in result if r.resource_id == object_id_pass)
            assert result_fail.status == "FAIL"
            assert result_pass.status == "PASS"

    def test_privileged_app_with_no_service_principal(self):
        """A FIC app whose service principal is not returned: expected PASS.

        Privileged status is derived from the service principal's Tier 0 role
        assignments; without a matching service principal the app cannot be
        confirmed privileged, so it must not be flagged.
        """
        object_id = str(uuid4())
        app_id = str(uuid4())
        app_name = "Orphan FIC App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_PATH, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_federated_credential_on_privileged_app.entra_app_registration_federated_credential_on_privileged_app import (
                entra_app_registration_federated_credential_on_privileged_app,
            )

            entra_client.app_registrations = {
                object_id: AppRegistration(
                    id=object_id,
                    app_id=app_id,
                    name=app_name,
                    federated_identity_credentials=[_fic()],
                )
            }
            entra_client.service_principals = {}

            check = entra_app_registration_federated_credential_on_privileged_app()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "no privileged (Tier 0) directory role" in result[0].status_extended

    def test_privileged_app_with_credentials_retrieval_error(self):
        """A privileged app whose FICs could not be read: expected MANUAL.

        A retrieval error leaves ``federated_identity_credentials`` empty, which
        must not be read as "no credentials" and reported PASS for a Tier 0 app.
        """
        object_id = str(uuid4())
        app_id = str(uuid4())
        app_name = "Unreadable Privileged App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_PATH, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_federated_credential_on_privileged_app.entra_app_registration_federated_credential_on_privileged_app import (
                entra_app_registration_federated_credential_on_privileged_app,
            )

            entra_client.app_registrations = {
                object_id: AppRegistration(
                    id=object_id,
                    app_id=app_id,
                    name=app_name,
                    federated_identity_credentials=[],
                    federated_identity_credentials_error=(
                        "Unable to retrieve federated identity credentials from "
                        "Microsoft Graph (ODataError)"
                    ),
                )
            }
            entra_client.service_principals = {
                "sp-1": ServicePrincipal(
                    id="sp-1",
                    name=app_name,
                    app_id=app_id,
                    directory_role_template_ids=[TIER0_ROLE_ID],
                )
            }

            check = entra_app_registration_federated_credential_on_privileged_app()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "could not be retrieved" in result[0].status_extended
            assert "Control Plane (Tier 0)" in result[0].status_extended
            assert result[0].resource_name == app_name
            assert result[0].resource_id == object_id

    def test_non_privileged_app_with_credentials_retrieval_error(self):
        """A non-privileged app whose FICs could not be read: expected PASS.

        The retrieval error is immaterial when the app holds no Tier 0 role, so
        it must not escalate to MANUAL.
        """
        object_id = str(uuid4())
        app_id = str(uuid4())
        app_name = "Unreadable Non Privileged App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_PATH, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_federated_credential_on_privileged_app.entra_app_registration_federated_credential_on_privileged_app import (
                entra_app_registration_federated_credential_on_privileged_app,
            )

            entra_client.app_registrations = {
                object_id: AppRegistration(
                    id=object_id,
                    app_id=app_id,
                    name=app_name,
                    federated_identity_credentials=[],
                    federated_identity_credentials_error=(
                        "Unable to retrieve federated identity credentials from "
                        "Microsoft Graph (ODataError)"
                    ),
                )
            }
            entra_client.service_principals = {
                "sp-1": ServicePrincipal(
                    id="sp-1",
                    name=app_name,
                    app_id=app_id,
                    directory_role_template_ids=[],
                )
            }

            check = entra_app_registration_federated_credential_on_privileged_app()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
