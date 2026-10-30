import { z } from "zod";

import {
  REALTIME_COST_DELTA_RANGE,
  REALTIME_COST_RATIO_RANGE,
  REALTIME_MAX_FRAMEWORKS,
  REALTIME_MAX_SCOPE_TAGS,
  REALTIME_MIN_SEVERITY,
  REALTIME_MODE,
  type RealtimeNotifications,
  type RealtimePolicyInput,
} from "@/types/realtime";

const GITHUB_REPO = /^[\w.-]+\/[\w.-]+$/;
const IAC_PATH = /^[\w./@-]*$/;

const nonEmptyList = z.array(z.string().trim().min(1));

/** The cost anomaly signal's own settings; a policy and its own page share them. */
const costAnomalyShape = {
  cost_anomaly_enabled: z.boolean(),
  cost_anomaly_min_ratio: z
    .number({ error: "Enter a number." })
    .min(
      REALTIME_COST_RATIO_RANGE.min,
      `Must be between ${REALTIME_COST_RATIO_RANGE.min} and ${REALTIME_COST_RATIO_RANGE.max}.`,
    )
    .max(
      REALTIME_COST_RATIO_RANGE.max,
      `Must be between ${REALTIME_COST_RATIO_RANGE.min} and ${REALTIME_COST_RATIO_RANGE.max}.`,
    ),
  cost_anomaly_min_delta: z
    .number({ error: "Enter a number." })
    .min(
      REALTIME_COST_DELTA_RANGE.min,
      `Must be between ${REALTIME_COST_DELTA_RANGE.min} and ${REALTIME_COST_DELTA_RANGE.max} dollars.`,
    )
    .max(
      REALTIME_COST_DELTA_RANGE.max,
      `Must be between ${REALTIME_COST_DELTA_RANGE.min} and ${REALTIME_COST_DELTA_RANGE.max} dollars.`,
    ),
};

export const realtimeCostAnomalySchema = z.object(costAnomalyShape);

const idList = z.array(z.string().trim().min(1));

/**
 * Where alerts go. A channel that is turned on needs somewhere to send to; the
 * API repeats this and also checks the destinations exist and are confirmed.
 */
export const realtimeNotificationsSchema = z
  .object({
    min_severity: z.enum(Object.values(REALTIME_MIN_SEVERITY)),
    slack: z.object({ enabled: z.boolean(), channel_ids: idList }),
    email: z.object({ enabled: z.boolean(), recipient_ids: idList }),
  })
  .superRefine((notifications, ctx) => {
    if (
      notifications.slack.enabled &&
      !notifications.slack.channel_ids.length
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["slack"],
        message: "Select at least one Slack channel, or turn Slack alerts off.",
      });
    }
    if (
      notifications.email.enabled &&
      !notifications.email.recipient_ids.length
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["email"],
        message: "Select at least one recipient, or turn email alerts off.",
      });
    }
  });

/** Nothing is sent until a channel is turned on. */
export const DEFAULT_REALTIME_NOTIFICATIONS: RealtimeNotifications = {
  min_severity: REALTIME_MIN_SEVERITY.HIGH,
  slack: { enabled: false, channel_ids: [] },
  email: { enabled: false, recipient_ids: [] },
};

/**
 * What a policy may contain. Shared by the form (instant feedback) and the
 * server action (never trust the client); the API repeats the rules.
 */
const policyShape = {
  enabled: z.boolean(),
  mode: z.enum(Object.values(REALTIME_MODE)),
  dry_run: z.boolean(),
  min_severity: z.enum(Object.values(REALTIME_MIN_SEVERITY)),
  deny_checks: nonEmptyList,
  allow_regions: nonEmptyList,
  scope_tags: z.record(z.string(), z.string()).superRefine((tags, ctx) => {
    const entries = Object.entries(tags);
    if (entries.length > REALTIME_MAX_SCOPE_TAGS) {
      ctx.addIssue({
        code: "custom",
        message: `A scope can have at most ${REALTIME_MAX_SCOPE_TAGS} tags.`,
      });
    }
    entries.forEach(([key, value]) => {
      if (!key.trim() || !value.trim()) {
        ctx.addIssue({
          code: "custom",
          message: "Each scope tag needs both a key and a value.",
        });
      } else if (key.includes("=")) {
        ctx.addIssue({
          code: "custom",
          message: `The tag key "${key}" cannot contain "=".`,
        });
      }
    });
  }),
  iac_repo: z
    .string()
    .trim()
    .max(200)
    .refine((value) => value === "" || GITHUB_REPO.test(value), {
      message: 'Use the "owner/repo" form.',
    }),
  iac_path: z
    .string()
    .trim()
    .max(200)
    .refine((value) => IAC_PATH.test(value) && !value.includes(".."), {
      message: "Use a relative directory such as infra/terraform.",
    }),
  open_pr: z.boolean(),
  use_lighthouse: z.boolean(),
  frameworks: z
    .array(z.string().trim().min(1))
    .max(
      REALTIME_MAX_FRAMEWORKS,
      `Select at most ${REALTIME_MAX_FRAMEWORKS} frameworks.`,
    ),
  ...costAnomalyShape,
};

export const realtimePolicySchema = z
  .object({ ...policyShape, notifications: realtimeNotificationsSchema })
  .superRefine((policy, ctx) => {
    if (policy.open_pr && !policy.iac_repo) {
      ctx.addIssue({
        code: "custom",
        path: ["iac_repo"],
        message: "Pull requests need a repository to open them in.",
      });
    }
  });

/**
 * Any subset of a policy, for a section that saves on its own (the setup
 * wizard, the alerts section): fields left out keep their stored value.
 */
export const realtimePolicyPatchSchema = z
  .object({ ...policyShape, notifications: realtimeNotificationsSchema })
  .partial();

/** The first message per field, for display next to the inputs. */
export const policyFieldErrors = (
  input: RealtimePolicyInput,
): Record<string, string> => {
  const result = realtimePolicySchema.safeParse(input);
  if (result.success) return {};
  const errors: Record<string, string> = {};
  result.error.issues.forEach((issue) => {
    const field = String(issue.path[0] ?? "form");
    if (!errors[field]) errors[field] = issue.message;
  });
  return errors;
};

export interface ScopeRow {
  id: string;
  key: string;
  value: string;
}

export const newScopeRow = (key = "", value = ""): ScopeRow => ({
  id: crypto.randomUUID(),
  key,
  value,
});

/**
 * Editor rows to a scope. Fully empty rows are dropped; a half-filled row or
 * a repeated key is an error (the API allows one value per key).
 */
export const scopeRowsToTags = (
  rows: ScopeRow[],
): { tags: Record<string, string>; error?: string } => {
  const tags: Record<string, string> = {};
  for (const row of rows) {
    const key = row.key.trim();
    const value = row.value.trim();
    if (!key && !value) continue;
    if (!key || !value) {
      return { tags, error: "Each scope tag needs both a key and a value." };
    }
    if (key in tags) {
      return { tags, error: `The tag key "${key}" is used more than once.` };
    }
    tags[key] = value;
  }
  return { tags };
};

/** Comma, space or newline separated values, trimmed, unique, order kept. */
export const splitList = (raw: string): string[] =>
  Array.from(
    new Set(
      raw
        .split(/[\s,]+/)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  );

/** The policy a provider gets before anyone saves one (the API's safe defaults). */
export const DEFAULT_REALTIME_POLICY: RealtimePolicyInput = {
  enabled: false,
  mode: REALTIME_MODE.PR,
  dry_run: true,
  min_severity: REALTIME_MIN_SEVERITY.LOW,
  deny_checks: [],
  allow_regions: [],
  scope_tags: {},
  iac_repo: "",
  iac_path: "",
  open_pr: false,
  use_lighthouse: true,
  frameworks: [],
  cost_anomaly_enabled: false,
  cost_anomaly_min_ratio: 2,
  cost_anomaly_min_delta: 5,
  notifications: DEFAULT_REALTIME_NOTIFICATIONS,
};

const AWS_ROLE_ARN = /^arn:aws:iam::\d{12}:role\/[\w+=,.@/-]+$/;

/** Role and secrets for the credentials form; the API enforces the rest. */
export const realtimeCredentialSchema = z
  .object({
    role_arn: z.string().trim().optional(),
    external_id: z.string().trim().optional(),
    github_token: z.string().trim().optional(),
  })
  .superRefine((credential, ctx) => {
    const { role_arn, external_id, github_token } = credential;
    if (!role_arn && !github_token) {
      ctx.addIssue({
        code: "custom",
        path: ["role_arn"],
        message: "Enter a role ARN, a GitHub token, or both.",
      });
    }
    if (role_arn && !AWS_ROLE_ARN.test(role_arn)) {
      ctx.addIssue({
        code: "custom",
        path: ["role_arn"],
        message: "Must be an IAM role ARN (arn:aws:iam::<account>:role/...).",
      });
    }
    if (role_arn && !external_id) {
      ctx.addIssue({
        code: "custom",
        path: ["external_id"],
        message: "An external id is required with a role.",
      });
    }
  });

export const realtimeFeedSchema = z.object({
  queue_url: z
    .string()
    .trim()
    .refine((value) => value === "" || value.startsWith("https://sqs."), {
      message:
        "Must be an SQS queue URL (https://sqs.<region>.amazonaws.com/...).",
    }),
  region: z
    .string()
    .trim()
    .regex(/^[a-z]{2}(-[a-z]+)+-\d$/, "Use an AWS region such as us-east-1."),
});
