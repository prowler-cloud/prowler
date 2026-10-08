from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import AppRegistration
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_app_registration_redirect_uris_secure:
    """Tests for the entra_app_registration_redirect_uris_secure check."""

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
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {}

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 0

    def test_app_no_redirect_uris(self):
        """App with no redirect URIs configured: expected PASS."""
        app_id = str(uuid4())
        app_name = "Clean App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "no redirect URIs configured" in result[0].status_extended
            assert result[0].resource_id == app_id
            assert result[0].resource_name == app_name

    def test_app_with_all_secure_uris(self):
        """App with only secure redirect URIs: expected PASS."""
        app_id = str(uuid4())
        app_name = "Secure App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    web_redirect_uris=[
                        "https://portal.contoso.com/signin-oidc",
                        "https://app.contoso.com/callback",
                    ],
                    spa_redirect_uris=["http://localhost:3000"],
                    public_client_redirect_uris=[
                        "msal11111111-1111-1111-1111-111111111111://auth"
                    ],
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "all redirect URIs secure" in result[0].status_extended
            assert result[0].resource_id == app_id
            assert result[0].resource_name == app_name

    def test_app_with_http_non_localhost_uri(self):
        """App with an http:// URI on a non-localhost host: expected FAIL."""
        app_id = str(uuid4())
        app_name = "Http App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    web_redirect_uris=[
                        "http://portal.contoso.com/signin-oidc",
                    ],
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "uses http://" in result[0].status_extended
            assert "portal.contoso.com" in result[0].status_extended
            assert result[0].resource_id == app_id
            assert result[0].resource_name == app_name

    def test_app_with_http_localhost_allowed(self):
        """App with http://localhost: expected PASS (loopback is allowed)."""
        app_id = str(uuid4())
        app_name = "Localhost App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    spa_redirect_uris=[
                        "http://localhost:3000",
                        "http://127.0.0.1:8080",
                        "http://[::1]:5000",
                    ],
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == app_id

    def test_app_with_azurewebsites_uri(self):
        """App with a host on *.azurewebsites.net: expected FAIL."""
        app_id = str(uuid4())
        app_name = "Azure Web App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    web_redirect_uris=[
                        "https://legacy-portal.azurewebsites.net/signin-oidc",
                    ],
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "azurewebsites.net" in result[0].status_extended
            assert result[0].resource_id == app_id
            assert result[0].resource_name == app_name

    def test_app_with_bare_azurewebsites_domain(self):
        """App with host exactly azurewebsites.net (no subdomain): expected FAIL."""
        app_id = str(uuid4())
        app_name = "Bare Domain App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    web_redirect_uris=[
                        "https://azurewebsites.net/callback",
                    ],
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "azurewebsites.net" in result[0].status_extended

    def test_app_with_wildcard_uri(self):
        """App with a wildcard in the redirect URI: expected FAIL."""
        app_id = str(uuid4())
        app_name = "Wildcard App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    web_redirect_uris=[
                        "https://*.contoso.com/callback",
                    ],
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "wildcard" in result[0].status_extended
            assert result[0].resource_id == app_id

    def test_app_with_malformed_uri_no_scheme(self):
        """App with a malformed URI (no scheme): expected FAIL."""
        app_id = str(uuid4())
        app_name = "Malformed App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    web_redirect_uris=[
                        "just-a-path/callback",
                    ],
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "malformed URI" in result[0].status_extended
            assert result[0].resource_id == app_id
            assert result[0].resource_name == app_name

    def test_app_with_malformed_uri_no_host(self):
        """App with a malformed URI (scheme but no host): expected FAIL."""
        app_id = str(uuid4())
        app_name = "No Host App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    web_redirect_uris=[
                        "https:///callback",
                    ],
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "malformed URI" in result[0].status_extended

    def test_app_with_custom_scheme_public_client(self):
        """App with custom scheme public-client URIs: expected PASS."""
        app_id = str(uuid4())
        app_name = "Native App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    public_client_redirect_uris=[
                        "msal11111111-1111-1111-1111-111111111111://auth",
                        "ms-appx-web://Microsoft.AAD.BrokerPlugin/1234",
                        "brk-multihub://contoso",
                        "urn:ietf:wg:oauth:2.0:oob",
                        "com.company.app://callback",
                        "msauth.com.contoso.app://auth",
                    ],
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == app_id
            assert result[0].resource_name == app_name

    def test_app_with_multiple_insecure_uris(self):
        """App with multiple insecure redirect URIs: expected FAIL listing all."""
        app_id = str(uuid4())
        app_name = "Legacy Portal"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    web_redirect_uris=[
                        "http://portal.contoso.com/signin-oidc",
                        "https://legacy-portal.azurewebsites.net/signin-oidc",
                        "https://*.contoso.com/callback",
                    ],
                    spa_redirect_uris=["http://localhost:3000"],
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "3 insecure redirect URI(s)" in result[0].status_extended
            assert result[0].resource_name == app_name

    def test_multiple_apps_mixed_results(self):
        """Multiple apps: one secure, one insecure."""
        app_id_pass = str(uuid4())
        app_name_pass = "Secure App"
        app_id_fail = str(uuid4())
        app_name_fail = "Insecure App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {
                app_id_pass: AppRegistration(
                    id=app_id_pass,
                    app_id=str(uuid4()),
                    name=app_name_pass,
                    web_redirect_uris=["https://app.contoso.com/callback"],
                ),
                app_id_fail: AppRegistration(
                    id=app_id_fail,
                    app_id=str(uuid4()),
                    name=app_name_fail,
                    web_redirect_uris=[
                        "http://app.insecure.com/callback",
                    ],
                ),
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 2
            result_pass = next(r for r in result if r.resource_id == app_id_pass)
            result_fail = next(r for r in result if r.resource_id == app_id_fail)
            assert result_pass.status == "PASS"
            assert result_pass.resource_name == app_name_pass
            assert result_fail.status == "FAIL"
            assert result_fail.resource_name == app_name_fail

    def test_app_with_more_than_five_insecure_uris_truncated(self):
        """App with more than 5 insecure URIs: status_extended is truncated."""
        app_id = str(uuid4())
        app_name = "Many URIs App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            insecure_uris = [f"http://host{i}.example.com/callback" for i in range(7)]

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    web_redirect_uris=insecure_uris,
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "7 insecure redirect URI(s)" in result[0].status_extended
            assert "(and 2 more)" in result[0].status_extended

    def test_app_with_exactly_five_insecure_uris_no_truncation(self):
        """App with exactly 5 insecure URIs: all displayed, no truncation."""
        app_id = str(uuid4())
        app_name = "Five URIs App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            insecure_uris = [f"http://host{i}.example.com/callback" for i in range(5)]

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    web_redirect_uris=insecure_uris,
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "5 insecure redirect URI(s)" in result[0].status_extended
            assert "(and" not in result[0].status_extended

    def test_app_with_wildcard_in_path(self):
        """App with a wildcard in the path (not host): expected FAIL."""
        app_id = str(uuid4())
        app_name = "Wildcard Path App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    web_redirect_uris=[
                        "https://contoso.com/*/callback",
                    ],
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "wildcard" in result[0].status_extended

    def test_app_with_insecure_spa_redirect_uri(self):
        """App with insecure SPA redirect URI: expected FAIL."""
        app_id = str(uuid4())
        app_name = "Insecure SPA"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    spa_redirect_uris=[
                        "http://app.contoso.com:4200",
                    ],
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "uses http://" in result[0].status_extended

    def test_app_resource_name_falls_back_to_app_id(self):
        """App with no display name: resource_name falls back to app_id."""
        app_id = str(uuid4())
        app_app_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_redirect_uris_secure.entra_app_registration_redirect_uris_secure import (
                entra_app_registration_redirect_uris_secure,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=app_app_id,
                    name="",
                )
            }

            check = entra_app_registration_redirect_uris_secure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == app_app_id
