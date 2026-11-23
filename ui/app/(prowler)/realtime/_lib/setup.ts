import {
  frameworkLabel,
  modeLabel,
} from "@/app/(prowler)/realtime/_lib/display";
import {
  REALTIME_FEED_STATUS,
  REALTIME_MODE,
  REALTIME_SETUP_STEP,
  type RealtimeCredential,
  type RealtimeFeed,
  type RealtimeFramework,
  type RealtimeNotifications,
  type RealtimeNotificationTargets,
  type RealtimePolicy,
  type RealtimeSetupPayload,
  type RealtimeSetupStepId,
} from "@/app/(prowler)/realtime/_types";

/** Configuration sections, in page order; ids match the API's setup steps. */
export const CONFIG_SECTION = REALTIME_SETUP_STEP;
export type ConfigSection = RealtimeSetupStepId;

export const CONFIG_SECTION_ORDER: readonly ConfigSection[] = [
  CONFIG_SECTION.FEED,
  CONFIG_SECTION.ENFORCEMENT,
  CONFIG_SECTION.REMEDIATION,
  CONFIG_SECTION.ALERTS,
  CONFIG_SECTION.COST,
  CONFIG_SECTION.ACTIVATE,
];

export const CONFIG_SECTION_LABELS: Record<ConfigSection, string> = {
  [CONFIG_SECTION.FEED]: "Event feed",
  [CONFIG_SECTION.ENFORCEMENT]: "What to enforce",
  [CONFIG_SECTION.REMEDIATION]: "Remediation access",
  [CONFIG_SECTION.ALERTS]: "Alerts",
  [CONFIG_SECTION.COST]: "Cost anomalies",
  [CONFIG_SECTION.ACTIVATE]: "Activate",
};

export const STEP_STATE = {
  DONE: "done",
  CURRENT: "current",
  TODO: "todo",
} as const;
export type StepState = (typeof STEP_STATE)[keyof typeof STEP_STATE];

const isConfigSection = (value: unknown): value is ConfigSection =>
  CONFIG_SECTION_ORDER.includes(value as ConfigSection);

const stepOf = (setup: RealtimeSetupPayload, id: ConfigSection) =>
  setup.steps.find((step) => step.id === id);

const isStepDone = (setup: RealtimeSetupPayload, id: ConfigSection): boolean =>
  stepOf(setup, id)?.done ?? false;

export const isStepRequired = (
  setup: RealtimeSetupPayload,
  id: ConfigSection,
): boolean => stepOf(setup, id)?.required ?? false;

/** The section to open on load: the URL's, else the next required step until activated. */
export const initialOpenSection = (
  setup: RealtimeSetupPayload | null,
  requested: string | undefined,
): ConfigSection | null => {
  if (isConfigSection(requested)) return requested;
  if (!setup || setup.activated) return null;
  return setup.next_step;
};

/** The section to open after one is saved, while setup is not finished. */
export const sectionAfter = (
  section: ConfigSection,
  setup: RealtimeSetupPayload | null,
): ConfigSection | null => {
  if (!setup || setup.activated) return null;
  return (
    CONFIG_SECTION_ORDER[CONFIG_SECTION_ORDER.indexOf(section) + 1] ?? null
  );
};

export const stepState = (
  setup: RealtimeSetupPayload | null,
  id: ConfigSection,
): StepState => {
  if (!setup) return STEP_STATE.TODO;
  if (isStepDone(setup, id)) return STEP_STATE.DONE;
  return setup.next_step === id ? STEP_STATE.CURRENT : STEP_STATE.TODO;
};

export interface RequiredProgress {
  done: number;
  total: number;
}

export const requiredProgress = (
  setup: RealtimeSetupPayload | null,
): RequiredProgress => {
  const required = (setup?.steps ?? []).filter((step) => step.required);
  return {
    done: required.filter((step) => step.done).length,
    total: required.length,
  };
};

/** Required steps still open before Realtime can be activated. */
export const missingBeforeActivate = (
  setup: RealtimeSetupPayload | null,
): ConfigSection[] =>
  (setup?.steps ?? [])
    .filter(
      (step) =>
        step.required && !step.done && step.id !== CONFIG_SECTION.ACTIVATE,
    )
    .map((step) => step.id);

export const PREFLIGHT_LEVEL = {
  OK: "ok",
  INFO: "info",
  WARNING: "warning",
} as const;
export type PreflightLevel =
  (typeof PREFLIGHT_LEVEL)[keyof typeof PREFLIGHT_LEVEL];

export interface PreflightCheck {
  id: string;
  level: PreflightLevel;
  message: string;
  /** The section that fixes it, when there is one. */
  section?: ConfigSection;
}

export interface PreflightInput {
  policy: RealtimePolicy | null;
  feed: RealtimeFeed | null;
  credential: RealtimeCredential | null;
}

/** What activating would do with the current setup; the API checks none of it. */
export const preflightChecks = ({
  policy,
  feed,
  credential,
}: PreflightInput): PreflightCheck[] => {
  const checks: PreflightCheck[] = [];

  if (!feed) {
    checks.push({
      id: "feed",
      level: PREFLIGHT_LEVEL.INFO,
      message:
        "No event feed yet: a CloudTrail lookup feed, a few minutes behind, is created when you activate.",
      section: CONFIG_SECTION.FEED,
    });
  } else if (feed.status === REALTIME_FEED_STATUS.ERROR) {
    checks.push({
      id: "feed",
      level: PREFLIGHT_LEVEL.WARNING,
      message: "The last event feed check failed, so changes may be missed.",
      section: CONFIG_SECTION.FEED,
    });
  } else if (feed.status === REALTIME_FEED_STATUS.CONNECTED) {
    checks.push({
      id: "feed",
      level: PREFLIGHT_LEVEL.OK,
      message: "The event feed is connected.",
    });
  } else {
    checks.push({
      id: "feed",
      level: PREFLIGHT_LEVEL.INFO,
      message: "The event feed has not been checked yet.",
      section: CONFIG_SECTION.FEED,
    });
  }

  if (!policy) return checks;

  if (policy.mode === REALTIME_MODE.AUTO && !credential?.role_arn) {
    checks.push({
      id: "role",
      level: PREFLIGHT_LEVEL.WARNING,
      message: policy.dry_run
        ? "Fix automatically has no remediation role, so fixes would fail. Safe while dry run is on."
        : "Fix automatically has no remediation role, so every fix will fail.",
      section: CONFIG_SECTION.REMEDIATION,
    });
  }

  if (policy.mode !== REALTIME_MODE.MONITOR) {
    if (!policy.iac_repo) {
      checks.push({
        id: "repo",
        level: PREFLIGHT_LEVEL.INFO,
        message:
          "No repository is set, so code changes stay as proposals for a person.",
        section: CONFIG_SECTION.ENFORCEMENT,
      });
    } else if (policy.open_pr && !credential?.has_github_token) {
      checks.push({
        id: "token",
        level: PREFLIGHT_LEVEL.WARNING,
        message:
          "No GitHub token is stored, so pull requests cannot be opened and changes stay as proposals.",
        section: CONFIG_SECTION.REMEDIATION,
      });
    }
  }

  return checks;
};

const QUEUE_URL_REGION =
  /^https:\/\/sqs\.([a-z]{2}(?:-[a-z]+)+-\d)\.amazonaws\.com(?:\.cn)?\//;

/** The region inside an SQS queue URL, when it has one. */
export const regionFromQueueUrl = (url: string): string | null =>
  QUEUE_URL_REGION.exec(url.trim())?.[1] ?? null;

export const feedSummary = (feed: RealtimeFeed | null): string => {
  if (!feed)
    return "Not set up. Choose real time via SQS or CloudTrail lookup.";
  const source = feed.queue_url
    ? `Real time via SQS · ${feed.region}`
    : "CloudTrail lookup · a few minutes behind";
  return feed.status === REALTIME_FEED_STATUS.ERROR
    ? `${source} · last check failed`
    : source;
};

export const enforcementSummary = (
  policy: RealtimePolicy | null,
  catalog: RealtimeFramework[],
): string => {
  if (!policy) return "Not set up. Choose how Prowler responds to a change.";
  const parts = [modeLabel(policy.mode)];
  if (policy.mode === REALTIME_MODE.AUTO && policy.dry_run) {
    parts.push("dry run");
  }
  parts.push(
    policy.frameworks.length
      ? policy.frameworks.map((id) => frameworkLabel(id, catalog)).join(", ")
      : "every check",
  );
  parts.push(`${policy.min_severity} and above`);
  return parts.join(" · ");
};

export const remediationSummary = (
  credential: RealtimeCredential | null,
): string => {
  if (!credential?.role_arn && !credential?.has_github_token) {
    return "No role yet. Prowler can alert and propose code changes, but cannot fix the account.";
  }
  return [
    credential.role_arn ? "Remediation role set" : "No remediation role",
    credential.has_github_token ? "GitHub token stored" : "no GitHub token",
  ].join(" · ");
};

export const alertsSummary = (
  notifications: RealtimeNotifications | null,
  targets: RealtimeNotificationTargets | null,
): string => {
  if (!notifications) return "Off. Nothing is sent.";
  const slackNames = notifications.slack.channel_ids.map((id) => {
    const name = targets?.slack.find((item) => item.channel_id === id)?.name;
    return name ? `#${name.replace(/^#/, "")}` : id;
  });
  const parts = [
    notifications.slack.enabled
      ? `Slack ${slackNames.join(", ") || "on"}`
      : "Slack off",
    notifications.email.enabled
      ? `email to ${notifications.email.recipient_ids.length} recipient${
          notifications.email.recipient_ids.length === 1 ? "" : "s"
        }`
      : "email off",
  ];
  if (notifications.slack.enabled || notifications.email.enabled) {
    parts.push(`${notifications.min_severity} and above`);
  }
  return parts.join(" · ");
};

export const costSummary = (policy: RealtimePolicy | null): string =>
  policy?.cost_anomaly_enabled
    ? `On · at least ${policy.cost_anomaly_min_ratio}x and +$${policy.cost_anomaly_min_delta} over the daily average`
    : "Off. Cost Explorer bills each request, about every 6 hours.";
