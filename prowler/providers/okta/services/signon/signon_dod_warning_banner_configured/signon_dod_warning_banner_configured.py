from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.signon.signon_client import signon_client
from prowler.providers.okta.services.signon.signon_service import SignInPage

# Distinctive marker groups drawn from the DTM-08-060 Standard Mandatory
# DOD Notice and Consent Banner. The HTML can vary across brands, so the
# check looks for the banner's core ideas rather than requiring an exact
# string match.
BANNER_MARKER_GROUPS = (
    ("u.s. government", "us government"),
    ("information system", "information systems"),
    ("authorized use only", "authorized use"),
    (
        "subject to monitoring",
        "may be intercepted",
        "searched, monitored, and recorded",
        "consent to monitoring",
    ),
)


def _matched_banner_groups(content_lower: str) -> list[str]:
    matched_markers: list[str] = []
    for marker_group in BANNER_MARKER_GROUPS:
        for marker in marker_group:
            if marker in content_lower:
                matched_markers.append(marker)
                break
    return matched_markers


class signon_dod_warning_banner_configured(Check):
    """STIG V-273192 / OKTA-APP-000200.

    Okta must display the Standard Mandatory DOD Notice and Consent
    Banner (DTM-08-060) before granting access to the application. The
    check inspects each brand's sign-in page HTML returned by the Okta
    Management API, using the customized page when present and otherwise
    falling back to the default sign-in page.
    """

    def execute(self) -> list[CheckReportOkta]:
        org_domain = signon_client.provider.identity.org_domain
        findings: list[CheckReportOkta] = []

        if not signon_client.sign_in_pages:
            placeholder = SignInPage(
                brand_id="no-brands-detected",
                brand_name="(no brands detected)",
                is_customized=False,
            )
            report = CheckReportOkta(
                metadata=self.metadata(),
                resource=placeholder,
                org_domain=org_domain,
                resource_name=placeholder.brand_name,
                resource_id=placeholder.brand_id,
            )
            report.status = "MANUAL"
            report.status_extended = (
                "No Okta brands were retrieved from the Brands API. Verify "
                "the sign-in page for the organization displays the DOD "
                "Notice and Consent Banner (DTM-08-060) in the Admin Console."
            )
            findings.append(report)
            return findings

        for page in signon_client.sign_in_pages.values():
            report = CheckReportOkta(
                metadata=self.metadata(),
                resource=page,
                org_domain=org_domain,
                resource_name=page.brand_name or page.brand_id,
                resource_id=page.brand_id,
            )

            if page.fetch_error:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not retrieve the sign-in page for "
                    f"brand '{page.brand_name or page.brand_id}' ({page.fetch_error}). "
                    "Inspect the brand manually to confirm the "
                    "DOD Notice and Consent Banner (DTM-08-060) is displayed."
                )
                findings.append(report)
                continue

            if not page.page_content:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Sign-in page content for brand "
                    f"'{page.brand_name or page.brand_id}' could not be "
                    "retrieved from the Okta API. Verify the DOD Notice and "
                    "Consent Banner (DTM-08-060) manually in the Admin Console."
                )
                findings.append(report)
                continue

            page_type = "customized" if page.is_customized else "default"
            content_lower = page.page_content.lower()
            matches = _matched_banner_groups(content_lower)

            if len(matches) == len(BANNER_MARKER_GROUPS):
                report.status = "PASS"
                report.status_extended = (
                    f"DOD Notice and Consent Banner detected on the {page_type} "
                    f"sign-in page for brand '{page.brand_name or page.brand_id}' "
                    f"({len(matches)} of {len(BANNER_MARKER_GROUPS)} required "
                    "marker groups matched)."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"{page_type.title()} sign-in page for brand "
                    f"'{page.brand_name or page.brand_id}' does not contain "
                    "the DOD Notice and Consent Banner (DTM-08-060)."
                )
            findings.append(report)

        return findings
