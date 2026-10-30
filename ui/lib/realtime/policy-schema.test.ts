import { describe, expect, it } from "vitest";

import {
  DEFAULT_REALTIME_NOTIFICATIONS,
  DEFAULT_REALTIME_POLICY,
  newScopeRow,
  policyFieldErrors,
  realtimeCostAnomalySchema,
  realtimeCredentialSchema,
  realtimeNotificationsSchema,
  realtimePolicyPatchSchema,
  scopeRowsToTags,
  splitList,
} from "./policy-schema";

describe("policy schema", () => {
  it("accepts the safe defaults", () => {
    expect(policyFieldErrors(DEFAULT_REALTIME_POLICY)).toEqual({});
    expect(DEFAULT_REALTIME_POLICY).toMatchObject({
      mode: "pr",
      dry_run: true,
      enabled: false,
      use_lighthouse: true,
      frameworks: [],
      cost_anomaly_enabled: false,
      cost_anomaly_min_ratio: 2,
      cost_anomaly_min_delta: 5,
    });
  });

  it("allows at most five frameworks", () => {
    const five = ["a", "b", "c", "d", "e"];

    expect(
      policyFieldErrors({ ...DEFAULT_REALTIME_POLICY, frameworks: five }),
    ).toEqual({});
    expect(
      policyFieldErrors({
        ...DEFAULT_REALTIME_POLICY,
        frameworks: [...five, "f"],
      }).frameworks,
    ).toMatch(/at most 5/);
  });

  it("keeps cost thresholds inside the API ranges", () => {
    const check = (ratio: number, delta: number) =>
      realtimeCostAnomalySchema.safeParse({
        cost_anomaly_enabled: true,
        cost_anomaly_min_ratio: ratio,
        cost_anomaly_min_delta: delta,
      }).success;

    expect(check(1.1, 0)).toBe(true);
    expect(check(20, 100000)).toBe(true);
    expect(check(1.09, 5)).toBe(false);
    expect(check(20.1, 5)).toBe(false);
    expect(check(2, -1)).toBe(false);
    expect(check(2, 100000.01)).toBe(false);
    expect(check(Number.NaN, 5)).toBe(false);
    expect(
      policyFieldErrors({
        ...DEFAULT_REALTIME_POLICY,
        cost_anomaly_min_ratio: 25,
      }).cost_anomaly_min_ratio,
    ).toMatch(/between 1.1 and 20/);
  });

  it("rejects more than ten scope tags", () => {
    const scope_tags = Object.fromEntries(
      Array.from({ length: 11 }, (_, i) => [`k${i}`, "v"]),
    );

    expect(
      policyFieldErrors({ ...DEFAULT_REALTIME_POLICY, scope_tags }).scope_tags,
    ).toMatch(/at most 10/);
  });

  it("rejects a tag key with an equals sign and empty values", () => {
    expect(
      policyFieldErrors({
        ...DEFAULT_REALTIME_POLICY,
        scope_tags: { "a=b": "c" },
      }).scope_tags,
    ).toMatch(/cannot contain/);
    expect(
      policyFieldErrors({
        ...DEFAULT_REALTIME_POLICY,
        scope_tags: { a: " " },
      }).scope_tags,
    ).toMatch(/both a key and a value/);
  });

  it("requires owner/repo, and a repo when pull requests are on", () => {
    expect(
      policyFieldErrors({ ...DEFAULT_REALTIME_POLICY, iac_repo: "nope" })
        .iac_repo,
    ).toBeDefined();
    expect(
      policyFieldErrors({ ...DEFAULT_REALTIME_POLICY, open_pr: true }).iac_repo,
    ).toMatch(/repository/);
    expect(
      policyFieldErrors({
        ...DEFAULT_REALTIME_POLICY,
        open_pr: true,
        iac_repo: "acme/infra",
        iac_path: "infra/terraform",
      }),
    ).toEqual({});
  });

  it("rejects a path that climbs out of the repository", () => {
    expect(
      policyFieldErrors({ ...DEFAULT_REALTIME_POLICY, iac_path: "../x" })
        .iac_path,
    ).toBeDefined();
  });

  it("turns editor rows into tags, dropping blanks and flagging problems", () => {
    expect(
      scopeRowsToTags([
        newScopeRow("env", "prod"),
        newScopeRow(),
        newScopeRow("team", "a"),
      ]).tags,
    ).toEqual({ env: "prod", team: "a" });
    expect(scopeRowsToTags([newScopeRow("env", "")]).error).toBeDefined();
    expect(
      scopeRowsToTags([newScopeRow("env", "a"), newScopeRow("env", "b")]).error,
    ).toMatch(/more than once/);
  });

  it("splits lists on commas, spaces and newlines without duplicates", () => {
    expect(splitList("a, b\nc  a")).toEqual(["a", "b", "c"]);
    expect(splitList("")).toEqual([]);
  });

  it("requires a role to come with an external id and a valid ARN", () => {
    expect(realtimeCredentialSchema.safeParse({}).success).toBe(false);
    expect(
      realtimeCredentialSchema.safeParse({ role_arn: "arn:aws:iam::1:role/x" })
        .success,
    ).toBe(false);
    expect(
      realtimeCredentialSchema.safeParse({
        role_arn: "arn:aws:iam::123456789012:role/ProwlerRemediation",
      }).success,
    ).toBe(false);
    expect(
      realtimeCredentialSchema.safeParse({
        role_arn: "arn:aws:iam::123456789012:role/ProwlerRemediation",
        external_id: "abc",
      }).success,
    ).toBe(true);
    expect(
      realtimeCredentialSchema.safeParse({ github_token: "token" }).success,
    ).toBe(true);
  });

  describe("alerts", () => {
    const notifications = (
      overrides: Partial<typeof DEFAULT_REALTIME_NOTIFICATIONS>,
    ) => ({ ...DEFAULT_REALTIME_NOTIFICATIONS, ...overrides });

    it("sends nothing by default", () => {
      expect(DEFAULT_REALTIME_POLICY.notifications).toEqual(
        DEFAULT_REALTIME_NOTIFICATIONS,
      );
      expect(DEFAULT_REALTIME_NOTIFICATIONS.slack.enabled).toBe(false);
      expect(DEFAULT_REALTIME_NOTIFICATIONS.email.enabled).toBe(false);
      expect(
        realtimeNotificationsSchema.safeParse(DEFAULT_REALTIME_NOTIFICATIONS)
          .success,
      ).toBe(true);
    });

    it("needs a channel when Slack is on", () => {
      const result = realtimeNotificationsSchema.safeParse(
        notifications({ slack: { enabled: true, channel_ids: [] } }),
      );

      expect(result.success).toBe(false);
      expect(!result.success && result.error.issues[0]).toMatchObject({
        path: ["slack"],
        message: expect.stringMatching(/Slack channel/),
      });
    });

    it("needs a recipient when email is on", () => {
      expect(
        policyFieldErrors({
          ...DEFAULT_REALTIME_POLICY,
          notifications: notifications({
            email: { enabled: true, recipient_ids: [] },
          }),
        }).notifications,
      ).toMatch(/recipient/);
      expect(
        realtimeNotificationsSchema.safeParse(
          notifications({ email: { enabled: true, recipient_ids: [] } }),
        ).success,
      ).toBe(false);
    });

    it("lets a channel that is off keep its selection", () => {
      expect(
        realtimeNotificationsSchema.safeParse(
          notifications({ slack: { enabled: false, channel_ids: ["C1"] } }),
        ).success,
      ).toBe(true);
    });

    it("rejects an unknown severity", () => {
      expect(
        realtimeNotificationsSchema.safeParse({
          ...DEFAULT_REALTIME_NOTIFICATIONS,
          min_severity: "urgent",
        }).success,
      ).toBe(false);
    });

    it("is part of the policy and of its patch", () => {
      const bad = {
        ...DEFAULT_REALTIME_POLICY,
        notifications: notifications({
          slack: { enabled: true, channel_ids: [] },
        }),
      };

      expect(policyFieldErrors(bad).notifications).toMatch(/Slack channel/);
      expect(
        realtimePolicyPatchSchema.safeParse({ enabled: true }).data,
      ).toEqual({ enabled: true });
      expect(
        realtimePolicyPatchSchema.safeParse({
          notifications: bad.notifications,
        }).success,
      ).toBe(false);
    });
  });
});
