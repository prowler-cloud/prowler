import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  fetchMock,
  getAuthHeadersMock,
  handleApiErrorMock,
  handleApiResponseMock,
} = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
  handleApiErrorMock: vi.fn(),
  handleApiResponseMock: vi.fn(),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.test/api/v1",
  getAuthHeaders: getAuthHeadersMock,
  getErrorMessage: (error: unknown) =>
    error instanceof Error ? error.message : String(error),
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiError: handleApiErrorMock,
  handleApiResponse: handleApiResponseMock,
}));

import { ALERT_AGGREGATE_OPS, ALERT_TRIGGER_KINDS } from "../_types";

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

const lastFetchCall = (): { url: string; init: RequestInit } => {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  const [url, init] = call;
  return { url: String(url), init: (init ?? {}) as RequestInit };
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockResolvedValue(
    new Response(JSON.stringify({ data: [] }), {
      status: 200,
      headers: { "Content-Type": "application/vnd.api+json" },
    }),
  );
  getAuthHeadersMock.mockResolvedValue({
    Accept: "application/vnd.api+json",
    Authorization: "Bearer test-token",
    "Content-Type": "application/vnd.api+json",
  });
  handleApiResponseMock.mockResolvedValue({ data: [] });
  handleApiErrorMock.mockReturnValue({ error: "Unexpected error." });
});

describe("listAlerts", () => {
  it("returns whatever handleApiResponse returns", async () => {
    handleApiResponseMock.mockResolvedValue({
      data: [],
      meta: { pagination: { count: 0 } },
    });
    const result = await listAlerts({ "filter[enabled]": "true" });
    expect(result).toEqual({ data: [], meta: { pagination: { count: 0 } } });
  });

  it("forwards searchParams as query string", async () => {
    await listAlerts({ "filter[trigger]": "daily" });
    expect(lastFetchCall().url).toContain("filter%5Btrigger%5D=daily");
  });

  it("delegates network errors to handleApiError", async () => {
    fetchMock.mockRejectedValueOnce(new Error("boom"));
    handleApiErrorMock.mockReturnValueOnce({ error: "boom" });
    const result = await listAlerts();
    expect(handleApiErrorMock).toHaveBeenCalled();
    expect(result).toEqual({ error: "boom" });
  });
});

describe("createAlert", () => {
  it("posts a JSON:API envelope with schema_version", async () => {
    handleApiResponseMock.mockResolvedValue({
      data: {
        id: "alert-1",
        type: "alert-rules",
        attributes: { name: "n", trigger: "after_scan" },
      },
    });
    await createAlert({
      name: "Daily critical",
      trigger: ALERT_TRIGGER_KINDS.AFTER_SCAN,
      condition: {
        op: ALERT_AGGREGATE_OPS.ANY,
        filter: { severity: ["critical"] },
      },
    });
    const { init } = lastFetchCall();
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string);
    expect(body.data.type).toBe("alert-rules");
    expect(body.data.attributes.schema_version).toBe(1);
  });

  it("sends an empty recipient list when provided", async () => {
    await createAlert({
      name: "No recipients yet",
      trigger: ALERT_TRIGGER_KINDS.AFTER_SCAN,
      condition: {
        op: ALERT_AGGREGATE_OPS.ANY,
        filter: { severity: ["critical"] },
      },
      recipientEmails: [],
    });
    const body = JSON.parse(lastFetchCall().init.body as string);
    expect(body.data.attributes.recipient_emails).toEqual([]);
  });
});

describe("seedAlertRule", () => {
  it("posts a JSON:API seeding envelope to /seed", async () => {
    const filterBag = {
      "filter[severity__in]": "critical",
      "filter[sort]": "-severity",
    };
    await seedAlertRule(filterBag);
    const { url, init } = lastFetchCall();
    expect(url).toMatch(/\/alerts\/rules\/seed$/);
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      data: {
        type: "alert-rule-seedings",
        attributes: { filter_bag: filterBag },
      },
    });
  });
});

describe("updateAlert", () => {
  it("PATCHes the alert with the id in the URL", async () => {
    await updateAlert("alert-1", {
      name: "Updated",
      trigger: ALERT_TRIGGER_KINDS.DAILY,
      condition: {
        op: ALERT_AGGREGATE_OPS.ANY,
        filter: { severity: ["critical"] },
      },
    });
    const { url, init } = lastFetchCall();
    expect(url).toContain("/alerts/rules/alert-1");
    expect(init.method).toBe("PATCH");
  });
});

describe("deleteAlert", () => {
  it("issues a DELETE against the alert id", async () => {
    handleApiResponseMock.mockResolvedValue({ success: true, status: 204 });
    await deleteAlert("alert-1");
    const { init } = lastFetchCall();
    expect(init.method).toBe("DELETE");
  });
});

describe("enable / disable", () => {
  it("PATCHes enabled true to the alert rule endpoint", async () => {
    await enableAlert("alert-1");
    const { url, init } = lastFetchCall();
    expect(url).toMatch(/\/alerts\/rules\/alert-1$/);
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(init.body as string)).toEqual({
      data: {
        type: "alert-rules",
        id: "alert-1",
        attributes: { enabled: true },
      },
    });
  });

  it("PATCHes enabled false to the alert rule endpoint", async () => {
    await disableAlert("alert-1");
    const { url, init } = lastFetchCall();
    expect(url).toMatch(/\/alerts\/rules\/alert-1$/);
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(init.body as string)).toEqual({
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
    const condition = {
      op: ALERT_AGGREGATE_OPS.ANY,
      filter: { severity: ["critical"] },
    };
    await previewAlertCondition({ condition });
    const { url, init } = lastFetchCall();
    expect(url).toMatch(/\/alerts\/rules\/preview$/);
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual(
      expect.objectContaining({
        Accept: "application/vnd.api+json",
        "Content-Type": "application/vnd.api+json",
      }),
    );
    expect(JSON.parse(init.body as string)).toEqual({
      data: {
        type: "alert-rule-previews",
        attributes: { condition },
      },
    });
  });
});
