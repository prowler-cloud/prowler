import type { ProviderType } from "@/types/providers";

import type { CrossProviderApiFilters } from "../_types";

// Catalog of universal compliance frameworks served by the cross-provider
// endpoint. Hardcoded because the API has no listing endpoint for universal
// framework ids: when a new universal JSON ships in the SDK
// (prowler/compliance/<framework>.json), add an entry here.

export interface CrossProviderFrameworkEntry {
  /** Universal framework id used as filter[compliance_id]. */
  complianceId: string;
  /** Card/detail title; also the [compliancetitle] path segment and the
   *  key getComplianceIcon resolves the framework icon from. */
  title: string;
  version: string;
  description: string;
  /** Static fallback for the per-provider chips; the API response's
   *  compatible_providers is authoritative at runtime. */
  compatibleProviders: ProviderType[];
}

export const CROSS_PROVIDER_FRAMEWORKS: CrossProviderFrameworkEntry[] = [
  {
    complianceId: "csa_ccm_4.0",
    title: "CSA-CCM",
    version: "4.0",
    description:
      "CSA Cloud Controls Matrix v4.0 — a cybersecurity control framework with 197 control objectives across 17 domains.",
    compatibleProviders: ["aws", "azure", "gcp", "alibabacloud", "oraclecloud"],
  },
  {
    complianceId: "cis_controls_8.1",
    title: "CIS-Controls",
    version: "8.1",
    description:
      "CIS Critical Security Controls v8.1 — prioritized safeguards organized into 18 controls to mitigate the most prevalent cyber-attacks.",
    compatibleProviders: [
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
      "openstack",
      "vercel",
    ],
  },
  {
    complianceId: "dora_2022_2554",
    title: "DORA",
    version: "2022/2554",
    description:
      "Digital Operational Resilience Act (EU 2022/2554) — the EU framework for the digital operational resilience of the financial sector.",
    compatibleProviders: ["aws", "azure", "gcp", "alibabacloud", "cloudflare"],
  },
];

/** Resolves only canonical catalog links. Missing, unknown, or mismatched
 * identities must not reach the API as an `undefined` or unrelated filter. */
export const resolveCrossProviderFramework = (
  complianceId: string | undefined,
  title: string,
): CrossProviderFrameworkEntry | undefined =>
  CROSS_PROVIDER_FRAMEWORKS.find(
    (entry) => entry.complianceId === complianceId && entry.title === title,
  );

/** Cross-provider filter params forwarded from the overview into detail
 *  links (and consumed back by the detail page). */
const CROSS_PROVIDER_FILTER_PARAMS = [
  "filter[provider_type__in]",
  "filter[provider_id__in]",
  "filter[provider_groups__in]",
  "filter[region__in]",
] as const;

/** Parses the URL filter params every cross-provider endpoint accepts. Kept
 *  next to CROSS_PROVIDER_FILTER_PARAMS so the overview and detail islands
 *  build identical, typed filter objects. */
export const parseCrossProviderFilters = (
  searchParams: Record<string, string | string[] | undefined>,
): CrossProviderApiFilters => ({
  providerTypes:
    searchParams["filter[provider_type__in]"]?.toString() || undefined,
  providerIds: searchParams["filter[provider_id__in]"]?.toString() || undefined,
  providerGroups:
    searchParams["filter[provider_groups__in]"]?.toString() || undefined,
  regions: searchParams["filter[region__in]"]?.toString() || undefined,
});

export const buildCrossProviderDetailHref = (
  entry: Pick<
    CrossProviderFrameworkEntry,
    "complianceId" | "title" | "version"
  >,
  searchParams?: Record<string, string | string[] | undefined>,
): string => {
  const params = new URLSearchParams();
  params.set("mode", "cross-provider");
  params.set("complianceId", entry.complianceId);
  params.set("version", entry.version);

  for (const key of CROSS_PROVIDER_FILTER_PARAMS) {
    const value = searchParams?.[key]?.toString();
    if (value) params.set(key, value);
  }

  return `/compliance/${encodeURIComponent(entry.title)}?${params.toString()}`;
};
