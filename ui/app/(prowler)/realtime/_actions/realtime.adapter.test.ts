import { describe, expect, it } from "vitest";

import {
  toAction,
  toDemoPayload,
  toEvent,
  toNotifications,
  toNotificationTargets,
  toRemediation,
  toSetup,
  toFramework,
  toFieldErrors,
  toInsightPayload,
  toPage,
  toPolicy,
  toRequestBody,
} from "./realtime.adapter";

const resource = (attributes: Record<string, unknown>, extra = {}) => ({
  id: "id-1",
  type: "x",
  attributes,
  ...extra,
});

describe("realtime adapter", () => {
  it("maps a policy and falls back to the API's safe defaults", () => {
    const policy = toPolicy(
      resource(
        { enabled: true, mode: "bogus", scope_tags: { env: "prod" } },
        {
          relationships: {
            provider: { data: { id: "prov-1", type: "providers" } },
          },
        },
      ),
    );

    expect(policy).toMatchObject({
      id: "id-1",
      provider_id: "prov-1",
      enabled: true,
      mode: "pr",
      dry_run: true,
      min_severity: "low",
      scope_tags: { env: "prod" },
      deny_checks: [],
    });
  });

  it("maps the new policy fields and defaults them like the API", () => {
    expect(
      toPolicy(
        resource({
          use_lighthouse: false,
          frameworks: ["soc2_aws", 3],
          cost_anomaly_enabled: true,
          cost_anomaly_min_ratio: 3.5,
          cost_anomaly_min_delta: 12,
        }),
      ),
    ).toMatchObject({
      use_lighthouse: false,
      frameworks: ["soc2_aws"],
      cost_anomaly_enabled: true,
      cost_anomaly_min_ratio: 3.5,
      cost_anomaly_min_delta: 12,
    });
    expect(toPolicy(resource({}))).toMatchObject({
      use_lighthouse: true,
      frameworks: [],
      cost_anomaly_enabled: false,
      cost_anomaly_min_ratio: 2,
      cost_anomaly_min_delta: 5,
    });
  });

  it("maps a framework of the catalog", () => {
    expect(
      toFramework({
        id: "soc2_aws",
        type: "realtime-frameworks",
        attributes: { name: "SOC 2", version: "2017" },
      }),
    ).toEqual({ id: "soc2_aws", name: "SOC 2", version: "2017" });
    expect(toFramework({ id: "x_aws", type: "realtime-frameworks" })).toEqual({
      id: "x_aws",
      name: "x_aws",
      version: "",
    });
  });

  it("maps an action with its detection relationship", () => {
    const action = toAction(
      resource(
        { kind: "self_fix", status: "applied", revertible: true },
        { relationships: { detection: { data: { id: "d1", type: "x" } } } },
      ),
    );

    expect(action.detection_id).toBe("d1");
    expect(action.revertible).toBe(true);
  });

  it("keeps the event id as the resource id and a null detection", () => {
    const event = toEvent(resource({ event_name: "RunInstances" }));

    expect(event.id).toBe("id-1");
    expect(event.detection_status).toBeNull();
    expect(event.rule_id).toBeNull();
  });

  it("builds a page from JSON:API pagination meta", () => {
    const page = toPage(
      {
        data: [resource({ kind: "code", status: "queued" })],
        meta: { pagination: { page: 2, pages: 3, count: 61 } },
      },
      toAction,
    );

    expect(page).toMatchObject({ page: 2, pages: 3, count: 61 });
    expect(page.items).toHaveLength(1);
  });

  it("returns an insight payload only for the requested kind", () => {
    const document = {
      data: resource({ kind: "simulation", payload: { open: 3 } }),
    };

    expect(toInsightPayload(document, "simulation")).toEqual({ open: 3 });
    expect(toInsightPayload(document, "overview")).toBeNull();
    expect(toInsightPayload(undefined, "overview")).toBeNull();
  });

  it("keys field errors by attribute name from the pointer", () => {
    expect(
      toFieldErrors([
        {
          detail: "Unknown severity.",
          source: { pointer: "/data/attributes/min_severity" },
        },
        { detail: "General" },
        {
          detail: "Second",
          source: { pointer: "/data/attributes/min_severity" },
        },
      ]),
    ).toEqual({ min_severity: "Unknown severity." });
  });

  it("builds a JSON:API body with the provider relationship only when given", () => {
    expect(
      toRequestBody({
        type: "realtime-policies",
        attributes: { mode: "pr" },
        providerId: "p1",
      }),
    ).toEqual({
      data: {
        type: "realtime-policies",
        attributes: { mode: "pr" },
        relationships: { provider: { data: { type: "providers", id: "p1" } } },
      },
    });
    expect(
      toRequestBody({ type: "t", id: "i", attributes: {} }).data,
    ).not.toHaveProperty("relationships");
  });

  it("reads the alert settings of a policy and defaults to sending nothing", () => {
    expect(toPolicy(resource({})).notifications).toEqual({
      min_severity: "high",
      slack: { enabled: false, channel_ids: [] },
      email: { enabled: false, recipient_ids: [] },
    });
    expect(
      toPolicy(
        resource({
          notifications: {
            min_severity: "critical",
            slack: { enabled: true, channel_ids: ["C1", 2] },
            email: { enabled: true, recipient_ids: ["r1"] },
          },
        }),
      ).notifications,
    ).toEqual({
      min_severity: "critical",
      slack: { enabled: true, channel_ids: ["C1"] },
      email: { enabled: true, recipient_ids: ["r1"] },
    });
    expect(toNotifications("nonsense").slack.enabled).toBe(false);
  });

  it("reads alert destinations from a single resource or a one-element list", () => {
    const attributes = {
      slack: [
        { integration_id: "i1", channel_id: "C1", name: "security" },
        { integration_id: "i1", name: "no id" },
      ],
      email: [
        { id: "r1", email: "a@example.com", status: "confirmed" },
        { id: "r2", email: "b@example.com", status: "pending" },
      ],
    };
    const expected = {
      slack: [{ integration_id: "i1", channel_id: "C1", name: "security" }],
      email: [
        { id: "r1", email: "a@example.com", status: "confirmed" },
        { id: "r2", email: "b@example.com", status: "pending" },
      ],
    };

    expect(toNotificationTargets({ data: resource(attributes) })).toEqual(
      expected,
    );
    expect(toNotificationTargets({ data: [resource(attributes)] })).toEqual(
      expected,
    );
    expect(toNotificationTargets(undefined)).toEqual({ slack: [], email: [] });
  });

  it("maps a remediation", () => {
    expect(
      toRemediation({
        id: "security-group-ingress",
        type: "realtime-remediations",
        attributes: {
          title: "Close open security group rules",
          effect: "Removes the rule",
          checks: ["a", "b"],
          active_checks: ["a"],
          iam_actions: ["ec2:RevokeSecurityGroupIngress"],
          revertible: true,
          undo: "Adds the rule back",
          in_enforced_scope: true,
        },
      }),
    ).toEqual({
      id: "security-group-ingress",
      title: "Close open security group rules",
      effect: "Removes the rule",
      checks: ["a", "b"],
      active_checks: ["a"],
      iam_actions: ["ec2:RevokeSecurityGroupIngress"],
      revertible: true,
      undo: "Adds the rule back",
      in_enforced_scope: true,
    });
  });

  it("maps the setup progress and drops unknown steps", () => {
    expect(
      toSetup({
        data: resource({
          payload: {
            activated: false,
            next_step: "enforcement",
            steps: [
              { id: "feed", required: true, done: true, detail: "SQS" },
              { id: "future", required: true, done: false, detail: null },
              { id: "alerts", required: false, done: false, detail: "" },
            ],
          },
        }),
      }),
    ).toEqual({
      activated: false,
      next_step: "enforcement",
      steps: [
        { id: "feed", required: true, done: true, detail: "SQS" },
        { id: "alerts", required: false, done: false, detail: null },
      ],
    });
    expect(toSetup({ data: resource({}) })).toBeNull();
    expect(
      toSetup({
        data: resource({ payload: { activated: true, next_step: null } }),
      }),
    ).toEqual({ activated: true, next_step: null, steps: [] });
  });

  it("reads demo insight payloads as they are", () => {
    const payload = { open: 3 };

    expect(
      toDemoPayload(
        { data: resource({ kind: "simulation", payload }) },
        "simulation",
      ),
    ).toEqual(payload);
    expect(
      toDemoPayload({ data: resource({ payload }) }, "simulation"),
    ).toEqual(payload);
    expect(
      toDemoPayload(
        { data: resource({ kind: "overview", payload }) },
        "simulation",
      ),
    ).toBeNull();
    expect(toDemoPayload({ data: resource({}) }, "status")).toBeNull();
  });

  it("maps demo list rows with the same mappers as the real lists", () => {
    const events = toDemoPayload(
      {
        data: resource({
          payload: {
            items: [
              {
                id: "e1",
                event_name: "RunInstances",
                read_only: false,
                provider_id: "demo",
              },
            ],
          },
        }),
      },
      "events",
    );
    const detections = toDemoPayload(
      {
        data: resource({
          payload: {
            items: [
              {
                id: "d1",
                title: "Open SG",
                status: "violation",
                provider_id: "demo",
              },
            ],
          },
        }),
      },
      "detections",
    );
    const actions = toDemoPayload(
      {
        data: resource({
          payload: {
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
        }),
      },
      "actions",
    );

    expect(events).toMatchObject({
      page: 1,
      pages: 1,
      count: 1,
      items: [{ id: "e1", event_name: "RunInstances", provider_id: "demo" }],
    });
    expect(detections?.items[0]).toMatchObject({
      id: "d1",
      status: "violation",
      provider_id: "demo",
    });
    expect(actions?.items[0]).toMatchObject({
      id: "a1",
      revertible: true,
      inserted_at: "2026-10-23T10:00:00Z",
    });
  });
});
