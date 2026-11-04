import { describe, expect, it } from "vitest";

import {
  REALTIME_FEED_SOURCE,
  REALTIME_MODE,
} from "@/app/(prowler)/realtime/_types";

import {
  credentialFormSchema,
  enforcementFormDefaults,
  enforcementFormSchema,
  feedFormSchema,
  toEnforcementPatch,
  toFeedInput,
} from "./configuration-forms";

const enforcement = (
  overrides: Partial<ReturnType<typeof enforcementFormDefaults>> = {},
) => ({ ...enforcementFormDefaults(null), ...overrides });

describe("enforcement form", () => {
  it("starts a new policy watching only, in dry run", () => {
    expect(enforcementFormDefaults(null)).toMatchObject({
      mode: REALTIME_MODE.MONITOR,
      dry_run: true,
    });
  });

  it("turns tag rows and lists into the policy's shape", () => {
    expect(
      toEnforcementPatch(
        enforcement({
          scope_tags: [
            { key: " env ", value: "prod" },
            { key: "", value: "" },
          ],
          deny_checks: "a, b\nb",
          allow_regions: "eu-west-1 us-east-1",
        }),
      ),
    ).toMatchObject({
      scope_tags: { env: "prod" },
      deny_checks: ["a", "b"],
      allow_regions: ["eu-west-1", "us-east-1"],
    });
  });

  it("never carries fields other sections own", () => {
    const patch = toEnforcementPatch(enforcement());
    expect(patch).not.toHaveProperty("enabled");
    expect(patch).not.toHaveProperty("notifications");
    expect(patch).not.toHaveProperty("cost_anomaly_enabled");
  });

  it("points each tag problem at its row", () => {
    const result = enforcementFormSchema.safeParse(
      enforcement({
        scope_tags: [
          { key: "env", value: "prod" },
          { key: "env", value: "dev" },
          { key: "a=b", value: "x" },
          { key: "team", value: "" },
        ],
      }),
    );
    const paths = result.success
      ? []
      : result.error.issues.map((issue) => issue.path.join("."));
    expect(paths).toEqual(
      expect.arrayContaining([
        "scope_tags.1.key",
        "scope_tags.2.key",
        "scope_tags.3.value",
      ]),
    );
  });

  it("needs a repository for pull requests, except in monitor mode", () => {
    expect(
      enforcementFormSchema.safeParse(
        enforcement({ mode: REALTIME_MODE.PR, open_pr: true }),
      ).success,
    ).toBe(false);
    expect(
      enforcementFormSchema.safeParse(
        enforcement({ mode: REALTIME_MODE.MONITOR, open_pr: true }),
      ).success,
    ).toBe(true);
  });
});

describe("feed form", () => {
  it("needs a queue URL for SQS and none for the lookup fallback", () => {
    expect(
      feedFormSchema.safeParse({
        source: REALTIME_FEED_SOURCE.SQS,
        queue_url: "",
        region: "us-east-1",
      }).success,
    ).toBe(false);
    expect(
      toFeedInput({
        source: REALTIME_FEED_SOURCE.LOOKUP,
        queue_url: "https://sqs.eu-west-1.amazonaws.com/1/q",
        region: "eu-west-1",
      }),
    ).toEqual({ queue_url: "", region: "eu-west-1" });
  });

  it("takes the region from the queue URL", () => {
    expect(
      toFeedInput({
        source: REALTIME_FEED_SOURCE.SQS,
        queue_url: "https://sqs.eu-west-1.amazonaws.com/123456789012/q",
        region: "us-east-1",
      }).region,
    ).toBe("eu-west-1");
  });
});

describe("credential form", () => {
  it("applies the shared credential rules to empty boxes", () => {
    expect(
      credentialFormSchema.safeParse({
        role_arn: "",
        external_id: "",
        github_token: "",
      }).success,
    ).toBe(false);
    expect(
      credentialFormSchema.safeParse({
        role_arn: "",
        external_id: "",
        github_token: "ghp_token",
      }).success,
    ).toBe(true);
  });
});
