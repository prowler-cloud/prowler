import re

from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.idp.idp_client import idp_client
from prowler.providers.okta.services.idp.idp_service import (
    SMART_CARD_IDP_TYPE,
    OktaIdentityProvider,
)
from prowler.providers.okta.services.idp.lib.idp_helpers import (
    missing_idps_scope_finding,
)

# Default issuer-DN substring patterns recognised as DOD-approved Certificate
# Authorities. The DOD PKI publishes canonical DN forms that include
# `O=U.S. Government, OU=DoD` (for DoD Root, DoD ID, DoD EMAIL, DoD SW, DoD
# JITC CAs) and `O=U.S. Government, OU=ECA` for the External Certificate
# Authorities. Customers running an internal CA outside these patterns can
# extend the list via the `okta_dod_approved_ca_issuer_patterns` audit-config
# entry — see the per-check Notes in metadata.json.
DEFAULT_DOD_CA_ISSUER_PATTERNS = (
    # `OU=DoD` is the distinctive DISA DN component for every CA in the DoD
    # PKI (Root, ID, EMAIL, SW, JITC). `OU=ECA` is the equivalent for the
    # External Certificate Authorities. The trailing `\b` prevents accidental
    # matches against superstrings like `OU=DoDExtra`.
    r"\bOU=DoD\b",
    r"\bOU=ECA\b",
)


class idp_smart_card_dod_approved_ca(Check):
    """Verifies that Okta Smart Card (X509) IdPs are configured and use a DOD-approved CA.

    PASS when the IdP is `ACTIVE` and its certificate chain's `issuer`
    DN matches one of the configured DOD-approved CA patterns. MANUAL
    when active but the issuer doesn't match (operator can verify
    out-of-band or extend the pattern list). FAIL when no Smart Card
    IdP is configured or when the configured IdP is inactive.
    """

    def execute(self) -> list[CheckReportOkta]:
        findings: list[CheckReportOkta] = []
        org_domain = idp_client.provider.identity.org_domain
        audit_config = idp_client.audit_config or {}
        configured_patterns = audit_config.get("okta_dod_approved_ca_issuer_patterns")
        patterns = (
            tuple(configured_patterns)
            if configured_patterns
            else DEFAULT_DOD_CA_ISSUER_PATTERNS
        )

        missing_scope = idp_client.missing_scope.get("identity_providers")
        if missing_scope:
            findings.append(
                missing_idps_scope_finding(self.metadata(), org_domain, missing_scope)
            )
            return findings

        smart_card_idps = [
            idp
            for idp in idp_client.identity_providers.values()
            if (idp.type or "").upper() == SMART_CARD_IDP_TYPE
        ]

        if not smart_card_idps:
            placeholder = OktaIdentityProvider(
                id="okta-smart-card-idp-missing",
                name="(no Smart Card IdP configured)",
                type=SMART_CARD_IDP_TYPE,
                status="MISSING",
            )
            report = CheckReportOkta(
                metadata=self.metadata(), resource=placeholder, org_domain=org_domain
            )
            report.status = "FAIL"
            report.status_extended = (
                "No Smart Card (X509) Identity Providers are configured. "
                "Configure a Smart Card IdP in the Admin Console "
                "(Security > Identity Providers) with a certificate chain "
                "issued by a DOD-approved CA. If CAC/PIV authentication is "
                "not required for this tenant, mutelist this check with "
                "that documented exception."
            )
            findings.append(report)
            return findings

        for idp in smart_card_idps:
            report = CheckReportOkta(
                metadata=self.metadata(), resource=idp, org_domain=org_domain
            )
            label = f"Okta Smart Card IdP '{idp.name}' (id={idp.id}, type={idp.type})"
            chain_detail = _format_chain_detail(idp)

            if (idp.status or "").upper() != "ACTIVE":
                report.status = "FAIL"
                report.status_extended = (
                    f"{label} is not ACTIVE (status={idp.status or 'unset'}). "
                    "Activate the IdP from Security > Identity Providers, then "
                    f"verify the certificate chain. {chain_detail}"
                )
                findings.append(report)
                continue

            matched_pattern = _matched_issuer_pattern(idp.trust_issuer, patterns)
            if matched_pattern is not None:
                report.status = "PASS"
                report.status_extended = (
                    f"{label} is ACTIVE and its chain issuer matches a "
                    f"DOD-approved CA pattern (`{matched_pattern}`). "
                    f"{chain_detail}"
                )
            else:
                report.status = "MANUAL"
                report.status_extended = (
                    f"{label} is ACTIVE but its chain issuer does not match any "
                    "configured DOD-approved CA pattern. Verify out-of-band "
                    "that the certificate chain belongs to a DOD-approved "
                    "Certificate Authority, or extend "
                    "`okta_dod_approved_ca_issuer_patterns` in the audit "
                    f"config. {chain_detail}"
                )
            findings.append(report)
        return findings


def _matched_issuer_pattern(issuer, patterns):
    if not issuer:
        return None
    for pattern in patterns:
        try:
            if re.search(pattern, issuer):
                return pattern
        except re.error:
            # Skip malformed operator-supplied patterns rather than crashing
            # the whole check.
            continue
    return None


def _format_chain_detail(idp: OktaIdentityProvider) -> str:
    if idp.trust_issuer or idp.trust_kid:
        return (
            f"Chain issuer: {idp.trust_issuer or 'unset'}; "
            f"kid: {idp.trust_kid or 'unset'}."
        )
    return (
        "Chain issuer and kid were not exposed by the API; inspect the IdP in "
        "the Admin Console under Security > Identity Providers > Configure."
    )
