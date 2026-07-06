const PROWLER_HUB_BASE_URL = "https://hub.prowler.com/compliance";

/**
 * Prowler Hub page for a universal compliance framework, keyed by its
 * ``compliance_id`` (e.g. ``cis_controls_8.1``) — same id the cross-provider
 * overview endpoint and ``UNIVERSAL_FRAMEWORKS`` catalogue already use, so no
 * separate mapping is needed per framework.
 */
export const getProwlerHubComplianceUrl = (complianceId: string): string =>
  `${PROWLER_HUB_BASE_URL}/${complianceId}`;
