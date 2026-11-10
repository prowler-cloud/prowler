import { describe, expect, it } from "vitest";

import { DEFAULT_REALTIME_POLICY } from "@/app/(prowler)/realtime/_lib/policy-schema";
import {
  REALTIME_FEED_STATUS,
  REALTIME_MODE,
  type RealtimeCredential,
  type RealtimeFeed,
  type RealtimePolicy,
  type RealtimeSetupPayload,
} from "@/app/(prowler)/realtime/_types";

import {
  CONFIG_SECTION,
  enforcementSummary,
  initialOpenSection,
  missingBeforeActivate,
  PREFLIGHT_LEVEL,
  preflightChecks,
  regionFromQueueUrl,
  requiredProgress,
  sectionAfter,
  STEP_STATE,
  stepState,
} from "./setup";

const setup = (
  done: Partial<Record<string, boolean>> = {},
  overrides: Partial<RealtimeSetupPayload> = {},
): RealtimeSetupPayload => ({
  activated: false,
  next_step: CONFIG_SECTION.FEED,
  steps: [
    { id: "feed", required: true, done: Boolean(done.feed), detail: null },
    {
      id: "enforcement",
      required: true,
      done: Boolean(done.enforcement),
      detail: null,
    },
    {
      id: "remediation",
      required: false,
      done: Boolean(done.remediation),
      detail: null,
    },
    { id: "alerts", required: false, done: Boolean(done.alerts), detail: null },
    { id: "cost", required: false, done: Boolean(done.cost), detail: null },
    {
      id: "activate",
      required: true,
      done: Boolean(done.activate),
      detail: null,
    },
  ],
  ...overrides,
});

const policy = (overrides: Partial<RealtimePolicy> = {}): RealtimePolicy => ({
  id: "policy-1",
  provider_id: "provider-1",
  ...DEFAULT_REALTIME_POLICY,
  ...overrides,
});

const feed = (overrides: Partial<RealtimeFeed> = {}): RealtimeFeed => ({
  id: "feed-1",
  provider_id: "provider-1",
  queue_url: "",
  region: "us-east-1",
  status: REALTIME_FEED_STATUS.CONNECTED,
  last_polled_at: null,
  last_event_at: null,
  last_error: "",
  ...overrides,
});

const credential = (
  overrides: Partial<RealtimeCredential> = {},
): RealtimeCredential => ({
  id: "cred-1",
  provider_id: "provider-1",
  role_arn: "",
  has_github_token: false,
  ...overrides,
});

describe("initialOpenSection", () => {
  it("opens the section the URL names", () => {
    expect(initialOpenSection(setup(), "alerts")).toBe("alerts");
  });

  it("opens the API's next step until Realtime is activated", () => {
    expect(
      initialOpenSection(
        setup({ feed: true }, { next_step: "enforcement" }),
        "nonsense",
      ),
    ).toBe("enforcement");
    expect(
      initialOpenSection(
        setup({}, { activated: true, next_step: null }),
        undefined,
      ),
    ).toBeNull();
  });
});

describe("progress", () => {
  it("counts only required steps", () => {
    expect(requiredProgress(setup({ feed: true, alerts: true }))).toEqual({
      done: 1,
      total: 3,
    });
  });

  it("lists the required steps missing before activation", () => {
    expect(missingBeforeActivate(setup({ feed: true }))).toEqual([
      "enforcement",
    ]);
    expect(
      missingBeforeActivate(setup({ feed: true, enforcement: true })),
    ).toEqual([]);
  });

  it("marks steps done, current or to do", () => {
    const current = setup({ feed: true }, { next_step: "enforcement" });
    expect(stepState(current, "feed")).toBe(STEP_STATE.DONE);
    expect(stepState(current, "enforcement")).toBe(STEP_STATE.CURRENT);
    expect(stepState(current, "cost")).toBe(STEP_STATE.TODO);
  });

  it("moves to the next section only while setting up", () => {
    expect(sectionAfter("feed", setup())).toBe("enforcement");
    expect(
      sectionAfter("feed", setup({}, { activated: true, next_step: null })),
    ).toBeNull();
  });
});

describe("preflightChecks", () => {
  it("says a lookup feed is created when there is none", () => {
    const [check] = preflightChecks({
      policy: null,
      feed: null,
      credential: null,
    });
    expect(check).toMatchObject({
      level: PREFLIGHT_LEVEL.INFO,
      message: expect.stringMatching(/created when you activate/),
    });
  });

  it("warns about a failed feed", () => {
    const [check] = preflightChecks({
      policy: null,
      feed: feed({ status: REALTIME_FEED_STATUS.ERROR }),
      credential: null,
    });
    expect(check.level).toBe(PREFLIGHT_LEVEL.WARNING);
  });

  it("warns that automatic fixes need a role, softer in dry run", () => {
    const checks = (dry_run: boolean) =>
      preflightChecks({
        policy: policy({ mode: REALTIME_MODE.AUTO, dry_run }),
        feed: feed(),
        credential: null,
      }).find((check) => check.id === "role");
    expect(checks(true)?.message).toMatch(/Safe while dry run/);
    expect(checks(false)?.message).toMatch(/every fix will fail/);
    expect(
      preflightChecks({
        policy: policy({ mode: REALTIME_MODE.AUTO }),
        feed: feed(),
        credential: credential({ role_arn: "arn:aws:iam::1:role/ProwlerX" }),
      }).find((check) => check.id === "role"),
    ).toBeUndefined();
  });

  it("explains that code changes stay as proposals without a repo or token", () => {
    const ids = (overrides: Partial<RealtimePolicy>, token = false) =>
      preflightChecks({
        policy: policy(overrides),
        feed: feed(),
        credential: credential({ has_github_token: token }),
      }).map((check) => check.id);

    expect(ids({ mode: REALTIME_MODE.PR, iac_repo: "" })).toContain("repo");
    expect(
      ids({ mode: REALTIME_MODE.PR, iac_repo: "acme/infra", open_pr: true }),
    ).toContain("token");
    expect(
      ids(
        { mode: REALTIME_MODE.PR, iac_repo: "acme/infra", open_pr: true },
        true,
      ),
    ).not.toContain("token");
    expect(ids({ mode: REALTIME_MODE.MONITOR, iac_repo: "" })).not.toContain(
      "repo",
    );
  });
});

describe("summaries", () => {
  it("reads the region out of a queue URL", () => {
    expect(
      regionFromQueueUrl(
        "https://sqs.eu-west-1.amazonaws.com/123456789012/prowler-realtime-events",
      ),
    ).toBe("eu-west-1");
    expect(regionFromQueueUrl("not a url")).toBeNull();
    // The host must end at amazonaws.com, so a lookalike domain is not a queue URL.
    expect(
      regionFromQueueUrl(
        "https://sqs.eu-west-1.amazonaws.com.evil.example/1/q",
      ),
    ).toBeNull();
  });

  it("names the frameworks and dry run in the enforcement summary", () => {
    expect(
      enforcementSummary(
        policy({
          mode: REALTIME_MODE.AUTO,
          dry_run: true,
          frameworks: ["soc2_aws"],
          min_severity: "high",
        }),
        [{ id: "soc2_aws", name: "SOC 2", version: "" }],
      ),
    ).toBe("Fix automatically · dry run · SOC 2 · high and above");
  });
});
