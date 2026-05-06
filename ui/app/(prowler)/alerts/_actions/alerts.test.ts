import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.test/api/v1",
  getAuthHeaders: vi.fn(async () => ({
    Accept: "application/vnd.api+json",
    Authorization: "Bearer test-token",
    "Content-Type": "application/vnd.api+json",
  })),
}));

vi.mock("next/cache", () => ({
  revalidatePath: vi.fn(),
  unstable_cache: <T extends (...args: unknown[]) => unknown>(fn: T) => fn,
}));

vi.mock("@sentry/nextjs", () => ({
  addBreadcrumb: vi.fn(),
  captureException: vi.fn(),
}));

import {
  ALERT_AGGREGATE_OPS,
  ALERT_ERROR_CODES,
  ALERT_TRIGGER_KINDS,
} from "../_types";
import {
  createAlert,
  deleteAlert,
  disableAlert,
  enableAlert,
  listAlerts,
  previewAlertCondition,
  seedAlertRule,
  updateAlert,
} from "./alerts";

const mockFetchOnce = (
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
) => {
  const response = new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/vnd.api+json",
      ...headers,
    },
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => response),
  );
};

const captureFetchArgs = (status: number, body: unknown) => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchMock = vi.fn(async (url: RequestInfo, init?: RequestInit) => {
    calls.push({ url: url.toString(), init: init ?? {} });
    return new Response(body === null ? null : JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/vnd.api+json" },
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  return calls;
};

beforeEach(() => {
  vi.unstubAllGlobals();
  process.env.NEXT_PUBLIC_IS_CLOUD_ENV = "true";
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("listAlerts", () => {
  it("returns a controlled error without fetching when alerts are disabled", async () => {
    process.env.NEXT_PUBLIC_IS_CLOUD_ENV = "false";
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const result = await listAlerts();

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe(ALERT_ERROR_CODES.FORBIDDEN);
      expect(result.error.status).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns the parsed list payload on success", async () => {
    mockFetchOnce(200, { data: [], meta: { pagination: { count: 0 } } });
    const result = await listAlerts(
      new URLSearchParams("filter[enabled]=true"),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.data).toEqual([]);
      expect(result.data.meta?.pagination?.count).toBe(0);
    }
  });

  it("forwards searchParams as query string", async () => {
    const calls = captureFetchArgs(200, { data: [] });
    await listAlerts(new URLSearchParams("filter[trigger]=daily"));
    expect(calls[0].url).toContain("filter%5Btrigger%5D=daily");
  });
});

describe("createAlert", () => {
  it("posts a JSON:API envelope and returns the new alert", async () => {
    const calls = captureFetchArgs(201, {
      data: {
        id: "alert-1",
        type: "alert-rules",
        attributes: { name: "n", trigger: "after_scan" },
      },
    });
    const result = await createAlert({
      name: "Daily critical",
      trigger: ALERT_TRIGGER_KINDS.AFTER_SCAN,
      condition: {
        op: ALERT_AGGREGATE_OPS.ANY,
        filter: { severity: ["critical"] },
      },
    });
    expect(result.ok).toBe(true);
    expect(calls[0].init.method).toBe("POST");
    const body = JSON.parse((calls[0].init.body as string) ?? "{}");
    expect(body.data.type).toBe("alert-rules");
    expect(body.data.attributes.schema_version).toBe(1);
  });

  it("surfaces JSON:API validation errors with the API code", async () => {
    mockFetchOnce(400, {
      errors: [
        {
          code: "unknown_filter_field",
          detail: "Unknown filter field 'foo'.",
          source: { pointer: "/data/attributes/condition/filter/foo" },
        },
      ],
    });
    const result = await createAlert({
      name: "x",
      trigger: ALERT_TRIGGER_KINDS.AFTER_SCAN,
      condition: {
        op: ALERT_AGGREGATE_OPS.ANY,
        filter: { severity: ["high"] },
      },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe(ALERT_ERROR_CODES.UNKNOWN_FILTER_FIELD);
    }
  });

  it("sends an empty recipient list when provided", async () => {
    const calls = captureFetchArgs(201, {
      data: {
        id: "alert-1",
        type: "alert-rules",
        attributes: { name: "n", trigger: "after_scan" },
      },
    });
    await createAlert({
      name: "No recipients yet",
      trigger: ALERT_TRIGGER_KINDS.AFTER_SCAN,
      condition: {
        op: ALERT_AGGREGATE_OPS.ANY,
        filter: { severity: ["critical"] },
      },
      recipientEmails: [],
    });

    const body = JSON.parse((calls[0].init.body as string) ?? "{}");
    expect(body.data.attributes.recipient_emails).toEqual([]);
  });
});

describe("seedAlertRule", () => {
  it("posts a JSON:API seeding envelope and normalizes the seed response", async () => {
    // Given
    const calls = captureFetchArgs(200, {
      data: {
        id: "seed",
        type: "alert-rule-seedings",
        attributes: {
          condition: {
            op: ALERT_AGGREGATE_OPS.ANY,
            filter: { severity: ["critical"] },
          },
          schema_version: 1,
          warnings: [{ field: "sort", reason: "ordering_not_supported" }],
        },
      },
    });
    const filterBag = {
      "filter[severity__in]": "critical",
      "filter[sort]": "-severity",
    };

    // When
    const result = await seedAlertRule(filterBag);

    // Then
    expect(result.ok).toBe(true);
    expect(calls[0].url).toMatch(/\/alerts\/rules\/seed$/);
    expect(calls[0].init.method).toBe("POST");
    expect(JSON.parse((calls[0].init.body as string) ?? "{}")).toEqual({
      data: {
        type: "alert-rule-seedings",
        attributes: { filter_bag: filterBag },
      },
    });
    if (result.ok) {
      expect(result.data).toEqual({
        condition: {
          op: ALERT_AGGREGATE_OPS.ANY,
          filter: { severity: ["critical"] },
        },
        schemaVersion: 1,
        warnings: [{ field: "sort", reason: "ordering_not_supported" }],
      });
    }
  });

  it("surfaces invalid seed errors from the API", async () => {
    // Given
    mockFetchOnce(400, {
      errors: [
        {
          code: "invalid_shape",
          detail: "At least one portable filter is required.",
        },
      ],
    });

    // When
    const result = await seedAlertRule({});

    // Then
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe(ALERT_ERROR_CODES.INVALID_SHAPE);
    }
  });
});

describe("updateAlert", () => {
  it("PATCHes the alert with the id in the URL", async () => {
    const calls = captureFetchArgs(200, {
      data: { id: "alert-1", type: "alert-rules", attributes: {} },
    });
    const result = await updateAlert("alert-1", {
      name: "Updated",
      trigger: ALERT_TRIGGER_KINDS.DAILY,
      condition: {
        op: ALERT_AGGREGATE_OPS.ANY,
        filter: { severity: ["critical"] },
      },
    });
    expect(result.ok).toBe(true);
    expect(calls[0].url).toContain("/alerts/rules/alert-1");
    expect(calls[0].init.method).toBe("PATCH");
  });
});

describe("deleteAlert", () => {
  it("returns ok on 204 without body", async () => {
    const calls = captureFetchArgs(204, null);
    const result = await deleteAlert("alert-1");
    expect(result.ok).toBe(true);
    expect(calls[0].init.method).toBe("DELETE");
  });
});

describe("enable / disable", () => {
  it("PATCHes enabled true to the alert rule endpoint", async () => {
    const calls = captureFetchArgs(200, {
      data: { id: "alert-1", type: "alert-rules", attributes: {} },
    });
    await enableAlert("alert-1");
    expect(calls[0].url).toMatch(/\/alerts\/rules\/alert-1$/);
    expect(calls[0].init.method).toBe("PATCH");
    const body = JSON.parse((calls[0].init.body as string) ?? "{}");
    expect(body).toEqual({
      data: {
        type: "alert-rules",
        id: "alert-1",
        attributes: { enabled: true },
      },
    });
  });

  it("PATCHes enabled false to the alert rule endpoint", async () => {
    const calls = captureFetchArgs(200, {
      data: { id: "alert-1", type: "alert-rules", attributes: {} },
    });
    await disableAlert("alert-1");
    expect(calls[0].url).toMatch(/\/alerts\/rules\/alert-1$/);
    expect(calls[0].init.method).toBe("PATCH");
    const body = JSON.parse((calls[0].init.body as string) ?? "{}");
    expect(body).toEqual({
      data: {
        type: "alert-rules",
        id: "alert-1",
        attributes: { enabled: false },
      },
    });
  });
});

describe("previewAlertCondition", () => {
  it("posts a JSON:API preview envelope to /preview", async () => {
    const calls = captureFetchArgs(200, { data: { attributes: {} } });
    const condition = {
      op: ALERT_AGGREGATE_OPS.ANY,
      filter: { severity: ["critical"] },
    };
    await previewAlertCondition({
      condition,
    });
    expect(calls[0].url).toMatch(/\/alerts\/rules\/preview$/);
    expect(calls[0].init.method).toBe("POST");
    expect(calls[0].init.headers).toEqual(
      expect.objectContaining({
        Accept: "application/vnd.api+json",
        "Content-Type": "application/vnd.api+json",
      }),
    );
    const body = JSON.parse((calls[0].init.body as string) ?? "{}");
    expect(body).toEqual({
      data: {
        type: "alert-rule-previews",
        attributes: { condition },
      },
    });
  });

  it("unwraps JSON:API preview attributes into the preview model", async () => {
    mockFetchOnce(200, {
      data: {
        type: "alert-rule-previews",
        id: "preview",
        attributes: {
          would_fire: true,
          summary: {
            finding_count_total: 7,
            top_severity: "critical",
          },
          sample_finding_ids: [],
          evaluation_failed: false,
          duration_ms: 42,
        },
      },
    });

    const result = await previewAlertCondition({
      condition: {
        op: ALERT_AGGREGATE_OPS.ANY,
        filter: { severity: ["critical"] },
      },
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.would_fire).toBe(true);
      expect(result.data.summary.finding_count_total).toBe(7);
      expect(result.data.duration_ms).toBe(42);
    }
  });
});
