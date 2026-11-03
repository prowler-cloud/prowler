/**
 * Cloudy feature registry.
 *
 * Upstream Prowler routes 17 features to a "Prowler Cloud" upsell modal when
 * the UI is self-hosted. Cloudy has no paid tier: every feature is either
 * available, or still being built in the open-source backend. Nothing is ever
 * sold from inside the product.
 *
 * - "available": the open-source API already serves this feature, so the UI
 *   always takes the real code path.
 * - "building":  the UI exists but the backend endpoints are not in the
 *   open-source API yet. Entry points are hidden (never upsold) until the
 *   backend lands and the status flips to "available".
 *
 * See docs/cloudy/ROADMAP.md for the backend work behind each "building" row.
 */
import type { UpgradeFeature } from "@/types/cloud-upgrade";

export type CloudyFeatureStatus = "available" | "building";

export const CLOUDY_FEATURE_STATUS: Record<
  UpgradeFeature,
  CloudyFeatureStatus
> = {
  // Backend present in the open-source API today.
  api_keys: "available", // TenantApiKeyViewSet
  jira_dispatch: "available", // single-finding dispatch; grouped dispatch is cloud-only today
  lighthouse_ai: "available", // bring-your-own LLM key (lighthouse/providers)
  report_download: "available",
  findings_preview: "available",
  general: "available",

  // UI exists, open-source backend still to be written (see roadmap).
  alerts: "building",
  saml_domains: "building", // OSS SAML config holds one email domain
  finding_triage: "building",
  cross_provider_compliance: "building",
  advanced_scheduling: "building",
  scan_configuration: "building",
  aws_organizations: "building",
  azure_organizations: "building",
  gcp_organizations: "building",
  cli_import: "building",
  registry: "building",
};

/**
 * Environment override so a deployment can switch on a feature as soon as its
 * backend ships, without a UI rebuild: CLOUDY_FEATURES="alerts,finding_triage".
 */
const readEnabledOverrides = (): Set<string> => {
  const raw =
    (typeof process !== "undefined" &&
      (process.env.NEXT_PUBLIC_CLOUDY_FEATURES ??
        process.env.CLOUDY_FEATURES)) ||
    "";
  return new Set(
    raw
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
  );
};

export function isFeatureAvailable(feature: UpgradeFeature): boolean {
  if (CLOUDY_FEATURE_STATUS[feature] === "available") return true;
  return readEnabledOverrides().has(feature);
}
