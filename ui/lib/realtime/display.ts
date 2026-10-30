import { demoAnomalyHref } from "@/lib/realtime/demo";
import {
  REALTIME_ACTION_STATUS,
  REALTIME_DRIFT_RULE_ID,
  REALTIME_DATA_STORE,
  REALTIME_DETECTION_STATUS,
  REALTIME_FEED_STATUS,
  REALTIME_MODE,
  REALTIME_ROUTE,
  type RealtimeActionStatus,
  type RealtimeDataStore,
  type RealtimeDetectionStatus,
  type RealtimeFeedStatus,
  type RealtimeMode,
  type RealtimeRoute,
} from "@/types/realtime";

/** Badge variants the shared `Badge` component defines. */
export const BADGE_TONE = {
  SUCCESS: "success",
  WARNING: "warning",
  ERROR: "error",
  INFO: "info",
  TAG: "tag",
  OUTLINE: "outline",
} as const;
export type BadgeTone = (typeof BADGE_TONE)[keyof typeof BADGE_TONE];

export interface BadgeDescriptor {
  label: string;
  tone: BadgeTone;
}

const ACTION_STATUS_BADGES: Record<RealtimeActionStatus, BadgeDescriptor> = {
  [REALTIME_ACTION_STATUS.DRY_RUN]: { label: "Dry run", tone: BADGE_TONE.INFO },
  [REALTIME_ACTION_STATUS.APPLIED]: {
    label: "Applied, verifying",
    tone: BADGE_TONE.INFO,
  },
  [REALTIME_ACTION_STATUS.FIXED_VERIFIED]: {
    label: "Fixed and verified",
    tone: BADGE_TONE.SUCCESS,
  },
  [REALTIME_ACTION_STATUS.FIX_FAILED]: {
    label: "Fix failed",
    tone: BADGE_TONE.ERROR,
  },
  [REALTIME_ACTION_STATUS.STILL_FAILING]: {
    label: "Applied, still failing",
    tone: BADGE_TONE.WARNING,
  },
  [REALTIME_ACTION_STATUS.PR_OPENED]: {
    label: "Pull request opened",
    tone: BADGE_TONE.SUCCESS,
  },
  [REALTIME_ACTION_STATUS.PR_READY]: {
    label: "Branch prepared",
    tone: BADGE_TONE.INFO,
  },
  [REALTIME_ACTION_STATUS.PR_BLOCKED]: {
    label: "Blocked by security gate",
    tone: BADGE_TONE.ERROR,
  },
  [REALTIME_ACTION_STATUS.QUEUED]: {
    label: "Queued for review",
    tone: BADGE_TONE.TAG,
  },
  [REALTIME_ACTION_STATUS.NOT_IN_CODE]: {
    label: "Not managed in code",
    tone: BADGE_TONE.WARNING,
  },
  [REALTIME_ACTION_STATUS.REVERTED]: {
    label: "Reverted",
    tone: BADGE_TONE.OUTLINE,
  },
};

export const actionStatusBadge = (status: string): BadgeDescriptor =>
  ACTION_STATUS_BADGES[status as RealtimeActionStatus] ?? {
    label: humanize(status),
    tone: BADGE_TONE.TAG,
  };

const DETECTION_STATUS_BADGES: Record<
  RealtimeDetectionStatus,
  BadgeDescriptor
> = {
  [REALTIME_DETECTION_STATUS.NEW]: {
    label: "Verifying",
    tone: BADGE_TONE.INFO,
  },
  [REALTIME_DETECTION_STATUS.VIOLATION]: {
    label: "Violation",
    tone: BADGE_TONE.ERROR,
  },
  [REALTIME_DETECTION_STATUS.COMPLIANT]: {
    label: "Compliant",
    tone: BADGE_TONE.SUCCESS,
  },
  [REALTIME_DETECTION_STATUS.OUT_OF_SCOPE]: {
    label: "Out of scope",
    tone: BADGE_TONE.OUTLINE,
  },
  [REALTIME_DETECTION_STATUS.ERROR]: {
    label: "Check failed",
    tone: BADGE_TONE.WARNING,
  },
};

export const detectionStatusBadge = (status: string): BadgeDescriptor =>
  DETECTION_STATUS_BADGES[status as RealtimeDetectionStatus] ?? {
    label: humanize(status),
    tone: BADGE_TONE.TAG,
  };

const ROUTE_BADGES: Record<RealtimeRoute, BadgeDescriptor> = {
  [REALTIME_ROUTE.AUTO]: { label: "Auto-fix", tone: BADGE_TONE.SUCCESS },
  [REALTIME_ROUTE.PR]: { label: "Pull request", tone: BADGE_TONE.INFO },
  [REALTIME_ROUTE.MANUAL]: {
    label: "Needs a person",
    tone: BADGE_TONE.WARNING,
  },
  [REALTIME_ROUTE.NOT_ENFORCED]: {
    label: "Not enforced",
    tone: BADGE_TONE.OUTLINE,
  },
};

/** What each route means, for the legend under the ranked findings. */
export const ROUTE_LEGEND: Record<RealtimeRoute, string> = {
  [REALTIME_ROUTE.AUTO]: "Fixed in the AWS account by Prowler Realtime.",
  [REALTIME_ROUTE.PR]: "A pull request proposes the change in your code.",
  [REALTIME_ROUTE.MANUAL]: "Nothing can be done safely without a person.",
  [REALTIME_ROUTE.NOT_ENFORCED]:
    "Outside the enforced compliance frameworks: detected and alerted, never changed.",
};

export const routeBadge = (route: string): BadgeDescriptor =>
  ROUTE_BADGES[route as RealtimeRoute] ?? {
    label: humanize(route),
    tone: BADGE_TONE.TAG,
  };

const FEED_STATUS_BADGES: Record<RealtimeFeedStatus, BadgeDescriptor> = {
  [REALTIME_FEED_STATUS.CONNECTED]: {
    label: "Connected",
    tone: BADGE_TONE.SUCCESS,
  },
  [REALTIME_FEED_STATUS.ERROR]: { label: "Error", tone: BADGE_TONE.ERROR },
  [REALTIME_FEED_STATUS.NOT_CONFIGURED]: {
    label: "Not configured",
    tone: BADGE_TONE.TAG,
  },
};

export const feedStatusBadge = (status: string): BadgeDescriptor =>
  FEED_STATUS_BADGES[status as RealtimeFeedStatus] ?? {
    label: humanize(status),
    tone: BADGE_TONE.TAG,
  };

const DATA_STORE_BADGES: Record<RealtimeDataStore, BadgeDescriptor> = {
  [REALTIME_DATA_STORE.OK]: {
    label: "Data store ready",
    tone: BADGE_TONE.SUCCESS,
  },
  [REALTIME_DATA_STORE.NOT_CONFIGURED]: {
    label: "Data store not configured",
    tone: BADGE_TONE.TAG,
  },
  [REALTIME_DATA_STORE.UNAVAILABLE]: {
    label: "Data store unavailable",
    tone: BADGE_TONE.ERROR,
  },
};

export const dataStoreBadge = (state: string): BadgeDescriptor =>
  DATA_STORE_BADGES[state as RealtimeDataStore] ?? {
    label: humanize(state),
    tone: BADGE_TONE.TAG,
  };

export interface ModeDescription {
  label: string;
  /** What choosing this mode means for the account, in plain language. */
  consequence: string;
}

export const MODE_DESCRIPTIONS: Record<RealtimeMode, ModeDescription> = {
  [REALTIME_MODE.MONITOR]: {
    label: "Monitor only",
    consequence:
      "Prowler Realtime watches and records risky changes and checks them against your compliance requirements. It never changes your account or your code.",
  },
  [REALTIME_MODE.PR]: {
    label: "Propose a change",
    consequence:
      "Prowler Realtime prepares a fix in your infrastructure code for review. Nothing in the AWS account is changed until you merge and deploy it.",
  },
  [REALTIME_MODE.AUTO]: {
    label: "Fix automatically",
    consequence:
      "Prowler Realtime fixes supported issues in the AWS account itself, using the remediation role, and records how to undo each change. Findings it cannot fix safely fall back to a pull request.",
  },
};

export const modeLabel = (mode: string): string =>
  MODE_DESCRIPTIONS[mode as RealtimeMode]?.label ?? humanize(mode);

/** A policy only changes the account when it is live, on and not in dry run. */
export const policyChangesAccount = (policy: {
  enabled: boolean;
  mode: string;
  dry_run: boolean;
}): boolean =>
  policy.enabled && policy.mode === REALTIME_MODE.AUTO && !policy.dry_run;

const SIGNAL_LABELS: Record<string, string> = {
  root_usage: "Root account activity",
  access_denied_burst: "Burst of denied API calls",
  external_ip_write: "Sensitive changes from outside AWS",
  recent_open_exposure: "Recent change that opens exposure",
};

export const signalLabel = (signal: string): string =>
  SIGNAL_LABELS[signal] ?? humanize(signal);

/** `access_denied_burst` to `Access denied burst`. */
export function humanize(value: string): string {
  const text = value.replace(/[_-]+/g, " ").trim();
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : "Unknown";
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"];

/** Severity counts as ordered entries, worst first, skipping zeroes. */
export const orderedSeverities = (
  counts: Record<string, number> | undefined,
): Array<[string, number]> =>
  Object.entries(counts ?? {})
    .filter(([, count]) => count > 0)
    .sort(
      ([a], [b]) =>
        (SEVERITY_ORDER.indexOf(a) === -1 ? 99 : SEVERITY_ORDER.indexOf(a)) -
        (SEVERITY_ORDER.indexOf(b) === -1 ? 99 : SEVERITY_ORDER.indexOf(b)),
    );

export const formatDateTime = (value: string | null | undefined): string => {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Unknown"
    : date.toLocaleString("en-US", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      });
};

/** `3 min ago`, `just now`, `2 h ago`, `4 d ago`. */
export const formatRelativeTime = (
  value: string | null | undefined,
  now: number = Date.now(),
): string => {
  if (!value) return "never";
  const time = new Date(value).getTime();
  if (Number.isNaN(time)) return "unknown";
  const seconds = Math.max(0, Math.round((now - time) / 1000));
  if (seconds < 45) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} h ago`;
  return `${Math.round(hours / 24)} d ago`;
};

export const formatMoney = (value: number | null | undefined): string =>
  `$${(value ?? 0).toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;

/** Only http(s) links are rendered as links; anything else is shown as text. */
export const safeExternalUrl = (value: string): string | null => {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:"
      ? url.toString()
      : null;
  } catch {
    return null;
  }
};

/** Why a panel is empty, from the status of the failing call. */
export const failureCopy = (
  status: number,
): { title: string; description: string } => {
  switch (status) {
    case 403:
      return {
        title: "You do not have access to this",
        description:
          "Your role cannot read this Prowler Realtime data. Ask an administrator for access.",
      };
    case 404:
      return {
        title: "Prowler Realtime is not available",
        description:
          "Prowler Realtime is not enabled for this deployment, or the AWS provider no longer exists.",
      };
    case 503:
      return {
        title: "Real-time data store not configured",
        description:
          "This view needs Prowler Realtime's event data store (ClickHouse), which is not configured or not reachable. Compliance checks, policies and remediation keep working without it.",
      };
    default:
      return {
        title: "Could not load this view",
        description: "Something went wrong while loading. Try again.",
      };
  }
};

/** Detections found by the reconciler rather than by a live event. */
export const isDriftDetection = (detection: { rule_id: string }): boolean =>
  detection.rule_id === REALTIME_DRIFT_RULE_ID;

const LIGHTHOUSE_SUMMARY_PREFIXES = [
  "Lighthouse AI fix",
  "Lighthouse AI proposal rejected",
];

/** Actions whose code change Lighthouse AI wrote (or whose proposal the gate refused). */
export const isLighthouseAction = (action: { summary: string }): boolean =>
  LIGHTHOUSE_SUMMARY_PREFIXES.some((prefix) =>
    action.summary.startsWith(prefix),
  );

/** The framework's name from the catalog, or its id while the catalog is missing. */
export const frameworkLabel = (
  id: string,
  catalog: Array<{ id: string; name: string }> = [],
): string => catalog.find((framework) => framework.id === id)?.name ?? id;

/** `<service>|<region>` to its parts; null when it is not an anomaly id. */
export const parseAnomalyId = (
  id: string,
): { service: string; region: string } | null => {
  const at = id.indexOf("|");
  if (at <= 0 || at === id.length - 1) return null;
  return { service: id.slice(0, at), region: id.slice(at + 1) };
};

/** The detail page of an anomaly; the id is URL-encoded. Sample anomalies have one fixed page. */
export const anomalyHref = (
  id: string,
  providerId: string,
  demo = false,
): string =>
  demo
    ? demoAnomalyHref(providerId || undefined)
    : `/realtime/cost-anomalies/${encodeURIComponent(id)}?provider=${encodeURIComponent(providerId)}`;

export const REALTIME_SETTINGS_PATH = "/realtime/settings";
export const REALTIME_COST_SETTINGS_PATH = "/realtime/settings/cost-anomalies";

export const settingsHref = (
  providerId?: string,
  path = REALTIME_SETTINGS_PATH,
) => (providerId ? `${path}?provider=${encodeURIComponent(providerId)}` : path);
