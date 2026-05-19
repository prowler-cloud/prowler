from unittest import mock

from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.signon.signon_fixtures import (
    DOD_BANNER_HTML_SNIPPET,
    build_signon_client,
    sign_in_page,
)

CHECK_PATH = (
    "prowler.providers.okta.services.signon."
    "signon_dod_warning_banner_configured."
    "signon_dod_warning_banner_configured.signon_client"
)


class Test_signon_dod_warning_banner_configured:
    def test_manual_when_no_brands_detected(self):
        signon_client = build_signon_client(sign_in_pages={})
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(CHECK_PATH, new=signon_client),
        ):
            from prowler.providers.okta.services.signon.signon_dod_warning_banner_configured.signon_dod_warning_banner_configured import (
                signon_dod_warning_banner_configured,
            )

            findings = signon_dod_warning_banner_configured().execute()
            assert len(findings) == 1
            assert findings[0].status == "MANUAL"
            assert "No Okta brands were retrieved" in findings[0].status_extended

    def test_pass_when_customized_page_contains_banner(self):
        page = sign_in_page(
            brand_id="brand-1",
            brand_name="Primary",
            is_customized=True,
            page_content=f"<html><body>{DOD_BANNER_HTML_SNIPPET}</body></html>",
        )
        signon_client = build_signon_client(sign_in_pages={"brand-1": page})
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(CHECK_PATH, new=signon_client),
        ):
            from prowler.providers.okta.services.signon.signon_dod_warning_banner_configured.signon_dod_warning_banner_configured import (
                signon_dod_warning_banner_configured,
            )

            findings = signon_dod_warning_banner_configured().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "DOD Notice and Consent Banner detected" in (
                findings[0].status_extended
            )

    def test_fail_when_customized_page_missing_banner(self):
        page = sign_in_page(
            brand_id="brand-1",
            brand_name="Primary",
            is_customized=True,
            page_content="<html><body><h1>Welcome to ACME</h1></body></html>",
        )
        signon_client = build_signon_client(sign_in_pages={"brand-1": page})
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(CHECK_PATH, new=signon_client),
        ):
            from prowler.providers.okta.services.signon.signon_dod_warning_banner_configured.signon_dod_warning_banner_configured import (
                signon_dod_warning_banner_configured,
            )

            findings = signon_dod_warning_banner_configured().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "does not contain" in findings[0].status_extended

    def test_manual_when_no_customization(self):
        page = sign_in_page(
            brand_id="brand-1",
            brand_name="Primary",
            is_customized=False,
            page_content=None,
        )
        signon_client = build_signon_client(sign_in_pages={"brand-1": page})
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(CHECK_PATH, new=signon_client),
        ):
            from prowler.providers.okta.services.signon.signon_dod_warning_banner_configured.signon_dod_warning_banner_configured import (
                signon_dod_warning_banner_configured,
            )

            findings = signon_dod_warning_banner_configured().execute()
            assert len(findings) == 1
            assert findings[0].status == "MANUAL"
            assert "No customized sign-in page" in findings[0].status_extended

    def test_manual_when_fetch_error(self):
        page = sign_in_page(
            brand_id="brand-1",
            brand_name="Primary",
            is_customized=False,
            fetch_error="403 Forbidden: invalid_scope",
        )
        signon_client = build_signon_client(sign_in_pages={"brand-1": page})
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(CHECK_PATH, new=signon_client),
        ):
            from prowler.providers.okta.services.signon.signon_dod_warning_banner_configured.signon_dod_warning_banner_configured import (
                signon_dod_warning_banner_configured,
            )

            findings = signon_dod_warning_banner_configured().execute()
            assert len(findings) == 1
            assert findings[0].status == "MANUAL"
            assert "Could not retrieve" in findings[0].status_extended
            assert "403" in findings[0].status_extended

    def test_emits_one_finding_per_brand(self):
        compliant = sign_in_page(
            brand_id="brand-prod",
            brand_name="Prod",
            is_customized=True,
            page_content=f"<html>{DOD_BANNER_HTML_SNIPPET}</html>",
        )
        missing = sign_in_page(
            brand_id="brand-sandbox",
            brand_name="Sandbox",
            is_customized=True,
            page_content="<html><body>No banner here</body></html>",
        )
        no_custom = sign_in_page(
            brand_id="brand-legacy",
            brand_name="Legacy",
            is_customized=False,
        )
        signon_client = build_signon_client(
            sign_in_pages={
                "brand-prod": compliant,
                "brand-sandbox": missing,
                "brand-legacy": no_custom,
            }
        )
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(CHECK_PATH, new=signon_client),
        ):
            from prowler.providers.okta.services.signon.signon_dod_warning_banner_configured.signon_dod_warning_banner_configured import (
                signon_dod_warning_banner_configured,
            )

            findings = signon_dod_warning_banner_configured().execute()
            assert len(findings) == 3
            by_brand = {f.resource_id: f.status for f in findings}
            assert by_brand == {
                "brand-prod": "PASS",
                "brand-sandbox": "FAIL",
                "brand-legacy": "MANUAL",
            }
