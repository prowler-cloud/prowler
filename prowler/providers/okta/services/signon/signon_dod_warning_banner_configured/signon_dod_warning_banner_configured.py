from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.signon.signon_client import signon_client


class signon_dod_warning_banner_configured(Check):
    """STIG V-273192 / OKTA-APP-000200.

    The DISA STIG requires the Okta sign-in widget/brand to display the
    Standard Mandatory DOD Notice and Consent Banner before login
    (DTM-08-060).

    The Okta Branding/Customization API allows partial verification of
    the sign-in page customization, but not all aspects of the banner
    content can be confirmed programmatically.  Therefore this check
    always returns a MANUAL status, instructing the administrator to
    visually confirm that the DOD banner is present and accurate.

    - MANUAL: The sign-in page customization cannot be fully verified
      via the API; manual review is required.
    """

    def execute(self) -> list[CheckReportOkta]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        org_domain = signon_client.provider.identity.org_domain

        report = CheckReportOkta(
            metadata=self.metadata(),
            resource=signon_client,
            resource_id=org_domain,
            resource_name=org_domain,
            org_domain=org_domain,
        )
        report.status = "MANUAL"
        report.status_extended = (
            f"Okta organization '{org_domain}' sign-in page customization "
            "cannot be fully verified via the API. Manually confirm that the "
            "Standard Mandatory DOD Notice and Consent Banner (DTM-08-060) "
            "is displayed before the login prompt."
        )

        return [report]
