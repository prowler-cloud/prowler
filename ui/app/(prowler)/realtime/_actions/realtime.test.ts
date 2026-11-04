import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, getAuthHeadersMock, handleApiResponseMock } = vi.hoisted(
  () => ({
    fetchMock: vi.fn(),
    getAuthHeadersMock: vi.fn(),
    handleApiResponseMock: vi.fn(),
  }),
);

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: handleApiResponseMock,
}));

import {
  getRealtimeCostAnomaly,
  getRealtimeDemo,
  getRealtimeEvents,
  getRealtimeFrameworks,
  getRealtimeInsight,
  getRealtimeNotificationTargets,
  getRealtimeRemediations,
  getRealtimeSetup,
  patchRealtimePolicy,
  pollRealtimeFeed,
  revertRealtimeAction,
  saveRealtimeCostSettings,
  saveRealtimeCredential,
  saveRealtimeNotifications,
  saveRealtimePolicy,
} from "./realtime";

const PROVIDER = "0b8c2b46-7f3a-4d1e-9a52-3f5f1d6a7c10";
const ACTION = "6f1d2c3b-1a2b-4c3d-8e9f-0a1b2c3d4e5f";

const NEW_FIELDS = {
  use_lighthouse: true,
  frameworks: [],
  cost_anomaly_enabled: false,
  cost_anomaly_min_ratio: 2,
  cost_anomaly_min_delta: 5,
  notifications: {
    min_severity: "high" as const,
    slack: { enabled: false, channel_ids: [] },
    email: { enabled: false, recipient_ids: [] },
  },
};

const json = (body: unknown, status: number) =>
  new Response(JSON.stringify(body), { status });

describe("realtime actions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  it("rejects a malformed provider id without calling the API", async () => {
    const result = await getRealtimeEvents({ providerId: "nope" });

    expect(result).toMatchObject({ ok: false, status: 400 });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("answers 503 from the event stream as an expected failure, not an error report", async () => {
    fetchMock.mockResolvedValue(
      json({ errors: [{ detail: "ClickHouse is not configured." }] }, 503),
    );

    const result = await getRealtimeEvents({ providerId: PROVIDER });

    expect(result).toEqual({
      ok: false,
      status: 503,
      error: "ClickHouse is not configured.",
    });
    expect(handleApiResponseMock).not.toHaveBeenCalled();
  });

  it("sends the provider, a bounded limit and the writes-only flag", async () => {
    fetchMock.mockResolvedValue(json({ data: [] }, 200));
    handleApiResponseMock.mockResolvedValue({ data: [] });

    await getRealtimeEvents({
      providerId: PROVIDER,
      limit: 9999,
      writesOnly: true,
    });

    const url = new URL(fetchMock.mock.calls[0][0]);
    expect(url.pathname).toBe("/api/v1/realtime/events");
    expect(url.searchParams.get("provider")).toBe(PROVIDER);
    expect(url.searchParams.get("limit")).toBe("500");
    expect(url.searchParams.get("writes_only")).toBe("true");
  });

  it("returns a 403 from the API as a failure the panel can explain", async () => {
    fetchMock.mockResolvedValue(json({}, 403));
    handleApiResponseMock.mockResolvedValue({
      error: "Forbidden",
      status: 403,
    });

    await expect(
      getRealtimeInsight("overview", PROVIDER),
    ).resolves.toMatchObject({ ok: false, status: 403 });
  });

  it("maps a cost insight payload", async () => {
    fetchMock.mockResolvedValue(json({}, 200));
    handleApiResponseMock.mockResolvedValue({
      data: {
        id: "cost:x",
        type: "realtime-insights",
        attributes: {
          kind: "cost",
          payload: { enabled: false },
        },
      },
    });

    const result = await getRealtimeInsight("cost", PROVIDER);

    expect(result.ok && result.data).toEqual({ enabled: false });
  });

  it("does not report a network failure as an exception", async () => {
    fetchMock.mockRejectedValue(new Error("boom"));

    await expect(getRealtimeInsight("status", PROVIDER)).resolves.toMatchObject(
      { ok: false, status: 0 },
    );
  });

  it("validates a policy before sending it", async () => {
    const result = await saveRealtimePolicy({
      providerId: PROVIDER,
      policy: {
        enabled: true,
        mode: "pr",
        dry_run: true,
        min_severity: "low",
        deny_checks: [],
        allow_regions: [],
        scope_tags: { "a=b": "c" },
        iac_repo: "",
        iac_path: "",
        open_pr: false,
        ...NEW_FIELDS,
      },
    });

    expect(result).toMatchObject({ ok: false, status: 400 });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("creates a policy with the provider relationship and patches an existing one", async () => {
    fetchMock.mockResolvedValue(json({}, 200));
    handleApiResponseMock.mockResolvedValue({
      data: { id: "pol", type: "realtime-policies", attributes: {} },
    });
    const policy = {
      enabled: false,
      mode: "pr" as const,
      dry_run: true,
      min_severity: "low" as const,
      deny_checks: [],
      allow_regions: [],
      scope_tags: {},
      iac_repo: "",
      iac_path: "",
      open_pr: false,
      ...NEW_FIELDS,
    };

    await saveRealtimePolicy({ providerId: PROVIDER, policy });
    await saveRealtimePolicy({
      providerId: PROVIDER,
      policyId: ACTION,
      policy,
    });

    const [create, update] = fetchMock.mock.calls;
    expect(create[1].method).toBe("POST");
    expect(JSON.parse(create[1].body).data.relationships.provider.data.id).toBe(
      PROVIDER,
    );
    expect(update[1].method).toBe("PATCH");
    expect(new URL(update[0]).pathname).toBe(
      `/api/v1/realtime/policies/${ACTION}`,
    );
  });

  it("leaves empty credential fields out of the request", async () => {
    fetchMock.mockResolvedValue(json({}, 201));
    handleApiResponseMock.mockResolvedValue({
      data: { id: "c", type: "realtime-credentials", attributes: {} },
    });

    await saveRealtimeCredential({
      providerId: PROVIDER,
      credential: {
        github_token: "ghp_example",
        role_arn: "",
        external_id: "",
      },
    });

    expect(JSON.parse(fetchMock.mock.calls[0][1].body).data.attributes).toEqual(
      { github_token: "ghp_example" },
    );
  });

  it("requires an external id with a role", async () => {
    const result = await saveRealtimeCredential({
      providerId: PROVIDER,
      credential: { role_arn: "arn:aws:iam::123456789012:role/ProwlerX" },
    });

    expect(result).toMatchObject({
      ok: false,
      fieldErrors: { external_id: expect.any(String) },
    });
  });

  it("surfaces the reason AWS refused a revert", async () => {
    fetchMock.mockResolvedValue(
      json(
        { errors: [{ detail: "The change could not be reverted: x" }] },
        409,
      ),
    );

    await expect(revertRealtimeAction(ACTION)).resolves.toEqual({
      ok: false,
      status: 409,
      error: "The change could not be reverted: x",
    });
  });

  it("treats the empty 202 of a poll as success", async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 202 }));
    handleApiResponseMock.mockResolvedValue({ success: true, status: 202 });

    await expect(pollRealtimeFeed(ACTION)).resolves.toEqual({
      ok: true,
      data: { queued: true },
    });
  });
  it("creates a policy from the cost page with only the cost fields, patches without touching the rest", async () => {
    fetchMock.mockResolvedValue(json({}, 200));
    handleApiResponseMock.mockResolvedValue({
      data: { id: "pol", type: "realtime-policies", attributes: {} },
    });
    const settings = {
      cost_anomaly_enabled: true,
      cost_anomaly_min_ratio: 3,
      cost_anomaly_min_delta: 10,
    };

    await saveRealtimeCostSettings({ providerId: PROVIDER, settings });
    await saveRealtimeCostSettings({
      providerId: PROVIDER,
      policyId: ACTION,
      settings,
    });

    const [create, update] = fetchMock.mock.calls;
    expect(create[1].method).toBe("POST");
    const created = JSON.parse(create[1].body).data;
    expect(created.attributes).toEqual(settings);
    expect(created.relationships.provider.data.id).toBe(PROVIDER);
    expect(update[1].method).toBe("PATCH");
    expect(JSON.parse(update[1].body).data.attributes).toEqual(settings);
  });

  it("rejects cost thresholds outside the API ranges without calling it", async () => {
    const tooLow = await saveRealtimeCostSettings({
      providerId: PROVIDER,
      settings: {
        cost_anomaly_enabled: true,
        cost_anomaly_min_ratio: 1.05,
        cost_anomaly_min_delta: 5,
      },
    });
    const tooHigh = await saveRealtimeCostSettings({
      providerId: PROVIDER,
      settings: {
        cost_anomaly_enabled: true,
        cost_anomaly_min_ratio: 2,
        cost_anomaly_min_delta: 100001,
      },
    });

    expect(tooLow).toMatchObject({
      ok: false,
      status: 400,
      fieldErrors: { cost_anomaly_min_ratio: expect.any(String) },
    });
    expect(tooHigh).toMatchObject({
      ok: false,
      fieldErrors: { cost_anomaly_min_delta: expect.any(String) },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("lists the frameworks of the catalog", async () => {
    fetchMock.mockResolvedValue(json({}, 200));
    handleApiResponseMock.mockResolvedValue({
      data: [
        {
          id: "soc2_aws",
          type: "realtime-frameworks",
          attributes: { name: "SOC 2", version: "2017" },
        },
      ],
    });

    const result = await getRealtimeFrameworks();

    expect(new URL(fetchMock.mock.calls[0][0]).pathname).toBe(
      "/api/v1/realtime/frameworks",
    );
    expect(result).toEqual({
      ok: true,
      data: [{ id: "soc2_aws", name: "SOC 2", version: "2017" }],
    });
  });

  it("asks for one anomaly by service and region, and passes 404 and 503 on", async () => {
    fetchMock.mockResolvedValue(json({}, 200));
    handleApiResponseMock.mockResolvedValue({
      data: {
        id: "anomaly:x",
        type: "realtime-insights",
        attributes: {
          kind: "anomaly",
          payload: { anomaly: null, series: [], events: [], findings: [] },
        },
      },
    });

    const result = await getRealtimeCostAnomaly({
      providerId: PROVIDER,
      service: "Amazon Elastic Compute Cloud - Compute",
      region: "eu-west-1",
    });

    const url = new URL(fetchMock.mock.calls[0][0]);
    expect(url.pathname).toBe("/api/v1/realtime/insights/anomaly");
    expect(url.searchParams.get("provider")).toBe(PROVIDER);
    expect(url.searchParams.get("service")).toBe(
      "Amazon Elastic Compute Cloud - Compute",
    );
    expect(url.searchParams.get("region")).toBe("eu-west-1");
    expect(result.ok).toBe(true);

    fetchMock.mockResolvedValue(
      json({ errors: [{ detail: "Not found." }] }, 404),
    );
    handleApiResponseMock.mockResolvedValue({
      error: "Not found.",
      status: 404,
    });
    await expect(
      getRealtimeCostAnomaly({
        providerId: PROVIDER,
        service: "s",
        region: "r",
      }),
    ).resolves.toMatchObject({ ok: false, status: 404 });

    fetchMock.mockResolvedValue(
      json({ errors: [{ detail: "No store." }] }, 503),
    );
    await expect(
      getRealtimeCostAnomaly({
        providerId: PROVIDER,
        service: "s",
        region: "r",
      }),
    ).resolves.toMatchObject({ ok: false, status: 503 });
  });

  it("does not call the API for a malformed anomaly request", async () => {
    await expect(
      getRealtimeCostAnomaly({ providerId: "nope", service: "s", region: "r" }),
    ).resolves.toMatchObject({ ok: false, status: 400 });
    await expect(
      getRealtimeCostAnomaly({
        providerId: PROVIDER,
        service: "",
        region: "r",
      }),
    ).resolves.toMatchObject({ ok: false, status: 404 });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  describe("alerts", () => {
    const NOTIFICATIONS = {
      min_severity: "high" as const,
      slack: { enabled: true, channel_ids: ["C1"] },
      email: { enabled: false, recipient_ids: [] },
    };
    const policyAnswer = {
      data: { id: "pol", type: "realtime-policies", attributes: {} },
    };

    it("sends the alert settings alone, so the rest of the policy is untouched", async () => {
      fetchMock.mockResolvedValue(json({}, 200));
      handleApiResponseMock.mockResolvedValue(policyAnswer);

      await saveRealtimeNotifications({
        providerId: PROVIDER,
        policyId: ACTION,
        notifications: NOTIFICATIONS,
      });

      const [url, init] = fetchMock.mock.calls[0];
      expect(init.method).toBe("PATCH");
      expect(new URL(url).pathname).toBe(`/api/v1/realtime/policies/${ACTION}`);
      expect(JSON.parse(init.body).data.attributes).toEqual({
        notifications: NOTIFICATIONS,
      });
    });

    it("creates the policy when there is none yet", async () => {
      fetchMock.mockResolvedValue(json({}, 201));
      handleApiResponseMock.mockResolvedValue(policyAnswer);

      await saveRealtimeNotifications({
        providerId: PROVIDER,
        notifications: NOTIFICATIONS,
      });

      expect(fetchMock.mock.calls[0][1].method).toBe("POST");
    });

    it("refuses a turned-on channel with nothing selected, without calling the API", async () => {
      const result = await saveRealtimeNotifications({
        providerId: PROVIDER,
        policyId: ACTION,
        notifications: {
          ...NOTIFICATIONS,
          slack: { enabled: true, channel_ids: [] },
        },
      });

      expect(result).toMatchObject({
        ok: false,
        status: 400,
        error: expect.stringMatching(/Slack channel/),
        fieldErrors: { notifications: expect.any(String) },
      });
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("surfaces the API's message for an unknown or unconfirmed destination", async () => {
      fetchMock.mockResolvedValue(json({}, 400));
      handleApiResponseMock.mockResolvedValue({
        error: "Unknown recipient",
        status: 400,
        errors: [
          {
            detail: "Recipient r9 is not confirmed.",
            source: { pointer: "/data/attributes/notifications" },
          },
        ],
      });

      const result = await saveRealtimeNotifications({
        providerId: PROVIDER,
        policyId: ACTION,
        notifications: NOTIFICATIONS,
      });

      expect(result).toMatchObject({
        ok: false,
        status: 400,
        fieldErrors: { notifications: "Recipient r9 is not confirmed." },
      });
    });

    it("carries the alert settings in a whole-policy save", async () => {
      fetchMock.mockResolvedValue(json({}, 200));
      handleApiResponseMock.mockResolvedValue(policyAnswer);

      await saveRealtimePolicy({
        providerId: PROVIDER,
        policyId: ACTION,
        policy: {
          enabled: false,
          mode: "pr",
          dry_run: true,
          min_severity: "low",
          deny_checks: [],
          allow_regions: [],
          scope_tags: {},
          iac_repo: "",
          iac_path: "",
          open_pr: false,
          ...NEW_FIELDS,
          notifications: NOTIFICATIONS,
        },
      });

      expect(
        JSON.parse(fetchMock.mock.calls[0][1].body).data.attributes
          .notifications,
      ).toEqual(NOTIFICATIONS);
    });

    it("rejects a whole-policy save with invalid alert settings", async () => {
      const result = await saveRealtimePolicy({
        providerId: PROVIDER,
        policy: {
          enabled: false,
          mode: "pr",
          dry_run: true,
          min_severity: "low",
          deny_checks: [],
          allow_regions: [],
          scope_tags: {},
          iac_repo: "",
          iac_path: "",
          open_pr: false,
          ...NEW_FIELDS,
          notifications: {
            ...NOTIFICATIONS,
            email: { enabled: true, recipient_ids: [] },
          },
        },
      });

      expect(result).toMatchObject({ ok: false, status: 400 });
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("reads the destinations", async () => {
      fetchMock.mockResolvedValue(json({}, 200));
      handleApiResponseMock.mockResolvedValue({
        data: [
          {
            id: "t",
            type: "realtime-notification-targets",
            attributes: {
              slack: [{ integration_id: "i", channel_id: "C1", name: "sec" }],
              email: [{ id: "r1", email: "a@example.com", status: "pending" }],
            },
          },
        ],
      });

      const result = await getRealtimeNotificationTargets();

      expect(new URL(fetchMock.mock.calls[0][0]).pathname).toBe(
        "/api/v1/realtime/notification-targets",
      );
      expect(result.ok && result.data.email[0].status).toBe("pending");
      expect(result.ok && result.data.slack[0].channel_id).toBe("C1");
    });
  });

  describe("patchRealtimePolicy", () => {
    it("sends only the fields it was given", async () => {
      fetchMock.mockResolvedValue(json({}, 200));
      handleApiResponseMock.mockResolvedValue({
        data: { id: "pol", type: "realtime-policies", attributes: {} },
      });

      await patchRealtimePolicy({
        providerId: PROVIDER,
        policyId: ACTION,
        patch: { enabled: true },
      });

      const [url, init] = fetchMock.mock.calls[0];
      expect(init.method).toBe("PATCH");
      expect(new URL(url).pathname).toBe(`/api/v1/realtime/policies/${ACTION}`);
      expect(JSON.parse(init.body).data.attributes).toEqual({ enabled: true });
    });

    it("validates the fields it was given", async () => {
      const result = await patchRealtimePolicy({
        providerId: PROVIDER,
        policyId: ACTION,
        patch: { scope_tags: { "a=b": "c" } },
      });

      expect(result).toMatchObject({ ok: false, status: 400 });
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("refuses a malformed policy id", async () => {
      await expect(
        patchRealtimePolicy({
          providerId: PROVIDER,
          policyId: "nope",
          patch: { enabled: true },
        }),
      ).resolves.toMatchObject({ ok: false, status: 400 });
    });
  });

  describe("remediations", () => {
    const answer = {
      data: [
        {
          id: "security-group-ingress",
          type: "realtime-remediations",
          attributes: {
            title: "Close open rules",
            effect: "e",
            checks: ["a"],
            active_checks: [],
            iam_actions: ["ec2:Revoke"],
            revertible: true,
            undo: "u",
            in_enforced_scope: false,
          },
        },
      ],
    };

    it("sends the provider when there is one", async () => {
      fetchMock.mockResolvedValue(json({}, 200));
      handleApiResponseMock.mockResolvedValue(answer);

      const result = await getRealtimeRemediations(PROVIDER);

      const url = new URL(fetchMock.mock.calls[0][0]);
      expect(url.pathname).toBe("/api/v1/realtime/remediations");
      expect(url.searchParams.get("provider")).toBe(PROVIDER);
      expect(result.ok && result.data[0].id).toBe("security-group-ingress");
    });

    it("asks without a provider in a demo or no-account context", async () => {
      fetchMock.mockResolvedValue(json({}, 200));
      handleApiResponseMock.mockResolvedValue(answer);

      await getRealtimeRemediations();

      expect(new URL(fetchMock.mock.calls[0][0]).search).toBe("");
    });

    it("rejects a malformed provider id", async () => {
      await expect(getRealtimeRemediations("nope")).resolves.toMatchObject({
        ok: false,
        status: 400,
      });
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("explains 403 and 503 as expected answers", async () => {
      fetchMock.mockResolvedValue(json({ errors: [{ detail: "x" }] }, 503));
      await expect(getRealtimeRemediations()).resolves.toMatchObject({
        ok: false,
        status: 503,
      });

      fetchMock.mockResolvedValue(json({}, 403));
      handleApiResponseMock.mockResolvedValue({ error: "no", status: 403 });
      await expect(getRealtimeRemediations()).resolves.toMatchObject({
        ok: false,
        status: 403,
      });
    });
  });

  describe("setup", () => {
    it("reads the wizard progress for a provider", async () => {
      fetchMock.mockResolvedValue(json({}, 200));
      handleApiResponseMock.mockResolvedValue({
        data: {
          id: "s",
          type: "realtime-insights",
          attributes: {
            kind: "setup",
            payload: {
              activated: false,
              next_step: "feed",
              steps: [
                { id: "feed", required: true, done: false, detail: null },
              ],
            },
          },
        },
      });

      const result = await getRealtimeSetup(PROVIDER);

      const url = new URL(fetchMock.mock.calls[0][0]);
      expect(url.pathname).toBe("/api/v1/realtime/insights/setup");
      expect(url.searchParams.get("provider")).toBe(PROVIDER);
      expect(result.ok && result.data.next_step).toBe("feed");
    });

    it("answers 404, 403 and 503 as failures, and rejects a bad provider", async () => {
      await expect(getRealtimeSetup("nope")).resolves.toMatchObject({
        status: 400,
      });
      fetchMock.mockResolvedValue(json({}, 503));
      await expect(getRealtimeSetup(PROVIDER)).resolves.toMatchObject({
        ok: false,
        status: 503,
      });
      fetchMock.mockResolvedValue(json({}, 404));
      handleApiResponseMock.mockResolvedValue({ error: "nf", status: 404 });
      await expect(getRealtimeSetup(PROVIDER)).resolves.toMatchObject({
        ok: false,
        status: 404,
      });
    });

    it("reports an unreadable answer", async () => {
      fetchMock.mockResolvedValue(json({}, 200));
      handleApiResponseMock.mockResolvedValue({ data: [] });

      await expect(getRealtimeSetup(PROVIDER)).resolves.toMatchObject({
        ok: false,
        status: 0,
      });
    });
  });

  describe("demo", () => {
    it("asks for sample data without a provider", async () => {
      fetchMock.mockResolvedValue(json({}, 200));
      handleApiResponseMock.mockResolvedValue({
        data: {
          id: "d",
          type: "realtime-insights",
          attributes: {
            kind: "status",
            payload: { demo: true, demo_notice: "made up", sha256: "x" },
          },
        },
      });

      const result = await getRealtimeDemo("status");

      const url = new URL(fetchMock.mock.calls[0][0]);
      expect(url.pathname).toBe("/api/v1/realtime/demo/status");
      expect(url.search).toBe("");
      expect(result.ok && result.data).toMatchObject({ demo: true });
    });

    it("returns the list kinds as one page of rows", async () => {
      fetchMock.mockResolvedValue(json({}, 200));
      handleApiResponseMock.mockResolvedValue({
        data: {
          id: "d",
          type: "realtime-insights",
          attributes: {
            kind: "actions",
            payload: {
              demo: true,
              items: [
                {
                  id: "a1",
                  kind: "self_fix",
                  status: "fixed_verified",
                  revertible: true,
                  inserted_at: "2026-10-23T10:00:00Z",
                },
              ],
            },
          },
        },
      });

      const result = await getRealtimeDemo("actions");

      expect(result.ok && result.data.items[0]).toMatchObject({
        id: "a1",
        revertible: true,
      });
      expect(result.ok && result.data.count).toBe(1);
    });

    it("rejects an unknown kind without calling the API", async () => {
      await expect(getRealtimeDemo("nope" as "status")).resolves.toMatchObject({
        ok: false,
        status: 404,
      });
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("answers a missing deployment as a notice, not an error", async () => {
      fetchMock.mockResolvedValue(json({}, 404));
      handleApiResponseMock.mockResolvedValue({ error: "nf", status: 404 });

      await expect(getRealtimeDemo("overview")).resolves.toMatchObject({
        ok: false,
        status: 404,
      });
    });
  });
});
