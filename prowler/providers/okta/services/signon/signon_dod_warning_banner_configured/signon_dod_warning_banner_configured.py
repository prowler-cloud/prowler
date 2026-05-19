from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.signon.signon_client import signon_client
from prowler.providers.okta.services.signon.signon_service import SignInPage

# Distinctive substrings drawn from the DTM-08-060 Standard Mandatory DOD
# Notice and Consent Banner. The full banner is ~1300 characters and is
# highly variable across HTML encodings, so the check matches on a
# tolerant marker set: a customized sign-in page is considered to carry
# the banner when at least two of these markers appear (case-insensitive).
BANNER_MARKERS = (
    "u.s. government",
    "usg information system",
    "only authorized use",
    "may be intercepted",
)
MIN_MARKER_MATCHES = 2


class signon_dod_warning_banner_configured(Check):
    """STIG V-273192 / OKTA-APP-000200.

    Okta must display the Standard Mandatory DOD Notice and Consent
    Banner (DTM-08-060) before granting access to the application. The
    check inspects each brand's customized sign-in page; tenants without
    a customized page fall through to MANUAL because the default Okta
    page content is not retrievable via the Management API.
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
                    f"Could not retrieve the customized sign-in page for "
                    f"brand '{page.brand_name or page.brand_id}' ({page.fetch_error}). "
                    "Inspect the brand customization manually to confirm the "
                    "DOD Notice and Consent Banner (DTM-08-060) is displayed."
                )
                findings.append(report)
                continue

            if not page.is_customized or not page.page_content:
                report.status = "MANUAL"
                report.status_extended = (
                    f"No customized sign-in page is configured for brand "
                    f"'{page.brand_name or page.brand_id}'. The DOD Notice "
                    "and Consent Banner cannot be audited via API — verify "
                    "the default sign-in page in the Admin Console."
                )
                findings.append(report)
                continue

            content_lower = page.page_content.lower()
            matches = sum(1 for marker in BANNER_MARKERS if marker in content_lower)

            if matches >= MIN_MARKER_MATCHES:
                report.status = "PASS"
                report.status_extended = (
                    f"DOD Notice and Consent Banner detected on the customized "
                    f"sign-in page for brand '{page.brand_name or page.brand_id}' "
                    f"({matches} of {len(BANNER_MARKERS)} marker phrases matched)."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Customized sign-in page for brand "
                    f"'{page.brand_name or page.brand_id}' does not contain "
                    "the DOD Notice and Consent Banner (DTM-08-060)."
                )
            findings.append(report)

        return findings
