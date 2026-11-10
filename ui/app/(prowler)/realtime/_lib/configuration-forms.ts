import { z } from "zod";

import {
  realtimeCredentialSchema,
  splitList,
} from "@/app/(prowler)/realtime/_lib/policy-schema";
import { regionFromQueueUrl } from "@/app/(prowler)/realtime/_lib/setup";
import {
  REALTIME_FEED_SOURCE,
  REALTIME_MAX_FRAMEWORKS,
  REALTIME_MAX_SCOPE_TAGS,
  REALTIME_MIN_SEVERITY,
  REALTIME_MODE,
  type RealtimeFeed,
  type RealtimeFeedInput,
  type RealtimePolicy,
  type RealtimePolicyInput,
} from "@/app/(prowler)/realtime/_types";

const GITHUB_REPO = /^[\w.-]+\/[\w.-]+$/;
const IAC_PATH = /^[\w./@-]*$/;
const AWS_REGION = /^[a-z]{2}(-[a-z]+)+-\d$/;
const DEFAULT_REGION = "us-east-1";

// ------------------------------------------------------------------- feed

export const feedFormSchema = z
  .object({
    source: z.enum(Object.values(REALTIME_FEED_SOURCE)),
    queue_url: z.string().trim(),
    region: z
      .string()
      .trim()
      .regex(AWS_REGION, "Use an AWS region such as us-east-1."),
  })
  .superRefine((values, ctx) => {
    if (values.source !== REALTIME_FEED_SOURCE.SQS) return;
    if (!values.queue_url) {
      ctx.addIssue({
        code: "custom",
        path: ["queue_url"],
        message: "Paste the queue URL from the stack outputs.",
      });
    } else if (!values.queue_url.startsWith("https://sqs.")) {
      ctx.addIssue({
        code: "custom",
        path: ["queue_url"],
        message:
          "Must be an SQS queue URL (https://sqs.<region>.amazonaws.com/...).",
      });
    }
  });

export type FeedFormValues = z.infer<typeof feedFormSchema>;

export const feedFormDefaults = (
  feed: RealtimeFeed | null,
): FeedFormValues => ({
  source:
    feed && !feed.queue_url
      ? REALTIME_FEED_SOURCE.LOOKUP
      : REALTIME_FEED_SOURCE.SQS,
  queue_url: feed?.queue_url ?? "",
  region: feed?.region || DEFAULT_REGION,
});

/** An empty queue URL selects the CloudTrail lookup fallback. */
export const toFeedInput = (values: FeedFormValues): RealtimeFeedInput =>
  values.source === REALTIME_FEED_SOURCE.LOOKUP
    ? { queue_url: "", region: values.region }
    : {
        queue_url: values.queue_url,
        region: regionFromQueueUrl(values.queue_url) ?? values.region,
      };

// ------------------------------------------------------------ enforcement

/** The policy fields the enforcement section owns; saves send only these. */
export const ENFORCEMENT_FIELDS = [
  "mode",
  "dry_run",
  "frameworks",
  "min_severity",
  "scope_tags",
  "deny_checks",
  "allow_regions",
  "iac_repo",
  "iac_path",
  "open_pr",
  "use_lighthouse",
] as const satisfies readonly (keyof RealtimePolicyInput)[];

export type EnforcementPatch = Pick<
  RealtimePolicyInput,
  (typeof ENFORCEMENT_FIELDS)[number]
>;

const scopeTagRow = z.object({ key: z.string(), value: z.string() });

export const enforcementFormSchema = z
  .object({
    mode: z.enum(Object.values(REALTIME_MODE)),
    dry_run: z.boolean(),
    frameworks: z
      .array(z.string())
      .max(
        REALTIME_MAX_FRAMEWORKS,
        `Select at most ${REALTIME_MAX_FRAMEWORKS} frameworks.`,
      ),
    min_severity: z.enum(Object.values(REALTIME_MIN_SEVERITY)),
    scope_tags: z
      .array(scopeTagRow)
      .max(
        REALTIME_MAX_SCOPE_TAGS,
        `A scope can have at most ${REALTIME_MAX_SCOPE_TAGS} tags.`,
      ),
    deny_checks: z.string(),
    allow_regions: z.string(),
    iac_repo: z
      .string()
      .trim()
      .max(200)
      .refine((value) => value === "" || GITHUB_REPO.test(value), {
        message: 'Use the "owner/repository" form.',
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
  })
  .superRefine((values, ctx) => {
    const seen = new Set<string>();
    values.scope_tags.forEach((row, index) => {
      const key = row.key.trim();
      const value = row.value.trim();
      if (!key && !value) return;
      if (!key) {
        ctx.addIssue({
          code: "custom",
          path: ["scope_tags", index, "key"],
          message: "Enter a key.",
        });
      } else if (key.includes("=")) {
        ctx.addIssue({
          code: "custom",
          path: ["scope_tags", index, "key"],
          message: 'A key cannot contain "=".',
        });
      } else if (seen.has(key)) {
        ctx.addIssue({
          code: "custom",
          path: ["scope_tags", index, "key"],
          message: "This key is already used.",
        });
      }
      if (!value) {
        ctx.addIssue({
          code: "custom",
          path: ["scope_tags", index, "value"],
          message: "Enter a value.",
        });
      }
      seen.add(key);
    });
    if (
      values.mode !== REALTIME_MODE.MONITOR &&
      values.open_pr &&
      !values.iac_repo
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["iac_repo"],
        message: "Pull requests need a repository to open them in.",
      });
    }
  });

export type EnforcementFormValues = z.infer<typeof enforcementFormSchema>;
export type ScopeTagRow = EnforcementFormValues["scope_tags"][number];

/** A new policy starts by watching only, in dry run. */
export const enforcementFormDefaults = (
  policy: RealtimePolicy | null,
): EnforcementFormValues => ({
  mode: policy?.mode ?? REALTIME_MODE.MONITOR,
  dry_run: policy?.dry_run ?? true,
  frameworks: policy?.frameworks ?? [],
  min_severity: policy?.min_severity ?? REALTIME_MIN_SEVERITY.LOW,
  scope_tags: Object.entries(policy?.scope_tags ?? {}).map(([key, value]) => ({
    key,
    value,
  })),
  deny_checks: (policy?.deny_checks ?? []).join("\n"),
  allow_regions: (policy?.allow_regions ?? []).join(", "),
  iac_repo: policy?.iac_repo ?? "",
  iac_path: policy?.iac_path ?? "",
  open_pr: policy?.open_pr ?? false,
  use_lighthouse: policy?.use_lighthouse ?? true,
});

export const toEnforcementPatch = (
  values: EnforcementFormValues,
): EnforcementPatch => ({
  mode: values.mode,
  dry_run: values.dry_run,
  frameworks: values.frameworks,
  min_severity: values.min_severity,
  scope_tags: Object.fromEntries(
    values.scope_tags
      .map((row) => [row.key.trim(), row.value.trim()] as const)
      .filter(([key, value]) => key && value),
  ),
  deny_checks: splitList(values.deny_checks),
  allow_regions: splitList(values.allow_regions),
  iac_repo: values.iac_repo.trim(),
  iac_path: values.iac_path.trim(),
  open_pr: values.open_pr,
  use_lighthouse: values.use_lighthouse,
});

// ------------------------------------------------------------ credentials

/** Every box is a string; the shared credential rules decide what is valid. */
export const credentialFormSchema = z
  .object({
    role_arn: z.string().trim(),
    external_id: z.string().trim(),
    github_token: z.string().trim(),
  })
  .superRefine((values, ctx) => {
    const result = realtimeCredentialSchema.safeParse(values);
    if (result.success) return;
    result.error.issues.forEach((issue) =>
      ctx.addIssue({
        code: "custom",
        path: issue.path,
        message: issue.message,
      }),
    );
  });

export type CredentialFormValues = z.infer<typeof credentialFormSchema>;

export const EMPTY_CREDENTIAL_FORM: CredentialFormValues = {
  role_arn: "",
  external_id: "",
  github_token: "",
};

// ------------------------------------------------------------------ cost

export interface CostFormValues {
  cost_anomaly_enabled: boolean;
  cost_anomaly_min_ratio: number;
  cost_anomaly_min_delta: number;
}

export const costFormDefaults = (
  policy: RealtimePolicy | null,
): CostFormValues => ({
  cost_anomaly_enabled: policy?.cost_anomaly_enabled ?? false,
  cost_anomaly_min_ratio: policy?.cost_anomaly_min_ratio ?? 2,
  cost_anomaly_min_delta: policy?.cost_anomaly_min_delta ?? 5,
});

/** A number input's text as a number; an empty box is NaN so zod asks for one. */
export const toNumber = (raw: string): number =>
  raw.trim() === "" ? Number.NaN : Number(raw);
