/**
 * Catalogue of universal compliance frameworks supported by the cross-provider
 * compliance roll-up endpoint.
 *
 * A universal framework is a single compliance specification (e.g. CSA Cloud
 * Controls Matrix v4.0) that declares per-provider check lists at the
 * requirement level. The backend exposes one row per provider it covers under
 * legacy ``<framework>_<provider>`` slugs while the universal id (without the
 * provider suffix) is the canonical handle for cross-provider aggregation.
 *
 * The list is hardcoded today because there is no API endpoint listing
 * universal framework ids. When a new universal JSON ships in
 * ``prowler/compliance/<framework>.json`` (matching the schema described in
 * ``docs/developer-guide/security-compliance-framework.mdx``), add an entry
 * here.
 */
export interface UniversalFrameworkCatalogEntry {
  /** Universal framework id used as ``filter[compliance_id]``. */
  id: string;
  /** Display title — kept aligned with the ``framework`` field exposed by the
   *  ``cross_provider`` endpoint so existing helpers (``getComplianceIcon``)
   *  resolve the same icon as the per-scan tab uses for the same framework. */
  title: string;
  /** Framework version surfaced in the card and detail header. */
  version: string;
  /** Short marketing-style description for the card subtitle. */
  description: string;
  /** Static list of providers the framework is documented to cover. The
   *  authoritative list at runtime is the ``compatible_providers`` field on
   *  the API response. */
  providers: string[];
}

export const UNIVERSAL_FRAMEWORKS: UniversalFrameworkCatalogEntry[] = [
  {
    id: "csa_ccm_4.0",
    title: "CSA-CCM",
    version: "4.0",
    description:
      "CSA Cloud Controls Matrix (CCM) v4.0 — a cybersecurity control " +
      "framework with 197 control objectives across 17 domains.",
    providers: ["aws", "azure", "gcp", "alibabacloud", "oraclecloud"],
  },
  {
    id: "cis_controls_8.1",
    title: "CIS-Controls",
    version: "8.1",
    description:
      "CIS Critical Security Controls v8.1 — a prioritized set of " +
      "safeguards organized into 18 controls to mitigate the most " +
      "prevalent cyber-attacks against systems and networks.",
    providers: [
      "aws",
      "azure",
      "gcp",
      "m365",
      "kubernetes",
      "github",
      "googleworkspace",
      "okta",
      "oraclecloud",
      "alibabacloud",
      "cloudflare",
      "mongodbatlas",
      "linode",
      "openstack",
      "stackit",
      "nhn",
      "scaleway",
      "vercel",
    ],
  },
  {
    id: "dora_2022_2554",
    title: "DORA",
    version: "2022/2554",
    description:
      "Digital Operational Resilience Act (Regulation (EU) 2022/2554) — " +
      "the EU framework for the digital operational resilience of the " +
      "financial sector.",
    providers: ["aws", "azure", "gcp", "alibabacloud", "cloudflare"],
  },
];

export const UNIVERSAL_FRAMEWORK_IDS: ReadonlySet<string> = new Set(
  UNIVERSAL_FRAMEWORKS.map((f) => f.id),
);

export const isUniversalFrameworkId = (
  complianceId: string | null | undefined,
): boolean => {
  if (!complianceId) return false;
  return UNIVERSAL_FRAMEWORK_IDS.has(complianceId);
};
