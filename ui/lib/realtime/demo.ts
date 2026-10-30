import type { RealtimePolicy } from "@/types/realtime";

export const REALTIME_PRODUCT_NAME_TEXT =
  "Prowler Realtime Detection and Remediation";

export const REALTIME_SETUP_PATH = "/realtime/setup";

/** The Lighthouse AI chat route (the sidebar's "Lighthouse AI" entry). */
export const LIGHTHOUSE_CHAT_PATH = "/lighthouse";

/** Shown in place of every write control while sample data is on screen. */
export const DEMO_TOOLTIP = "Demo data";

/** The path segment of the sample cost anomaly's detail page. */
export const DEMO_ANOMALY_SLUG = "demo";

/** The id of the anomaly in the sample data: `<service>|<region>`. */
export const DEMO_ANOMALY_ID =
  "Amazon Elastic Compute Cloud - Compute|us-east-1";

export const DEMO_BANNER_TITLE =
  "DEMO DATA — a made-up account shown until you set up Prowler Realtime";

/**
 * The dashboard shows sample data until the selected AWS account has a policy
 * that is switched on, or when there is no AWS account at all. `policy` is the
 * selected provider's policy, null when it has none.
 */
export const isRealtimeDemoMode = ({
  providerId,
  policy,
}: {
  providerId: string | undefined;
  policy: Pick<RealtimePolicy, "enabled"> | null | undefined;
}): boolean => !providerId || !policy?.enabled;

export const setupHref = (providerId?: string): string =>
  providerId
    ? `${REALTIME_SETUP_PATH}?provider=${encodeURIComponent(providerId)}`
    : REALTIME_SETUP_PATH;

export const demoAnomalyHref = (providerId?: string): string =>
  `/realtime/cost-anomalies/${DEMO_ANOMALY_SLUG}${
    providerId ? `?provider=${encodeURIComponent(providerId)}` : ""
  }`;
