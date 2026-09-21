import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { POST } from "./route";

// Browser MSW intercepts the same-origin request before Next can run this
// Route Handler, so these tests call POST directly.
const { getAuthHeadersMock, isCloudMock } = vi.hoisted(() => ({
  getAuthHeadersMock: vi.fn(),
  isCloudMock: vi.fn(),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/shared/env", () => ({
  isCloud: isCloudMock,
}));

// A browser upload always reaches the route with a length on the wire, and the
// route refuses anything it cannot measure, so a forwarded Request needs one.
const uploadRequest = (body = "report") =>
  new Request("http://localhost/api/ingestions", {
    method: "POST",
    headers: {
      "content-length": String(new TextEncoder().encode(body).length),
    },
    body,
  });

describe("POST /api/ingestions", () => {
  const server = setupServer();

  beforeAll(() => server.listen({ onUnhandledRequest: "error" }));

  afterEach(() => {
    server.resetHandlers();
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  afterAll(() => server.close());

  it("returns not found in OSS and Local Server without authenticating or forwarding the upload", async () => {
    isCloudMock.mockReturnValue(false);
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const request = new Request("http://localhost/api/ingestions", {
      method: "POST",
      headers: { "content-type": "multipart/form-data; boundary=report" },
      body: "--report--",
    });

    const response = await POST(request);

    expect(response.status).toBe(404);
    expect(request.body?.locked).toBe(false);
    expect(getAuthHeadersMock).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards the original multipart stream and boundary in Cloud", async () => {
    isCloudMock.mockReturnValue(true);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    let contentType: string | null = null;
    let contentLength: string | null = null;
    let uploadedBody = "";
    server.use(
      http.post(
        "https://api.example.com/api/v1/ingestions",
        async ({ request }) => {
          contentType = request.headers.get("content-type");
          contentLength = request.headers.get("content-length");
          uploadedBody = await request.text();
          return HttpResponse.json({
            data: {
              id: "ingestion-123",
              type: "ingestions",
              attributes: {
                status: "pending",
                summary: { total: 0, processed: 0, invalid: 0 },
                requested_at: "2026-08-26T11:23:20.265770Z",
                started_at: null,
                completed_at: null,
              },
            },
          });
        },
      ),
    );
    // Built by hand: a Request created from FormData carries no content-length
    // header, which is what this test pins.
    const boundary = "----ingestionBoundary";
    const multipartBody = [
      `--${boundary}`,
      'Content-Disposition: form-data; name="file"; filename="findings.ocsf.json"',
      "Content-Type: application/json",
      "",
      "finding report",
      `--${boundary}--`,
      "",
    ].join("\r\n");
    const request = new Request("http://localhost/api/ingestions", {
      method: "POST",
      headers: {
        "content-type": `multipart/form-data; boundary=${boundary}`,
        "content-length": String(
          new TextEncoder().encode(multipartBody).length,
        ),
      },
      body: multipartBody,
    });

    const response = await POST(request);

    expect(contentType).toBe(`multipart/form-data; boundary=${boundary}`);
    expect(contentLength).toBe(
      String(new TextEncoder().encode(multipartBody).length),
    );
    expect(uploadedBody).toBe(multipartBody);
    await expect(response.json()).resolves.toEqual({
      data: {
        id: "ingestion-123",
        status: "pending",
        totalRecords: 0,
        processedRecords: 0,
        invalidRecords: 0,
      },
    });
  });

  it("refuses an upload it cannot measure instead of forwarding it chunked", async () => {
    isCloudMock.mockReturnValue(true);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    // A Request built from FormData carries no content-length, and the ingestion
    // API parses no file out of the chunked body that would be forwarded.
    const request = new Request("http://localhost/api/ingestions", {
      method: "POST",
      headers: { "content-type": "multipart/form-data; boundary=report" },
      body: "--report--",
    });

    const response = await POST(request);

    expect(response.status).toBe(411);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(request.body?.locked).toBe(false);
    await expect(response.json()).resolves.toEqual({
      error: "Unable to start the import. Please try again.",
    });
  });

  it("sanitizes unexpected upstream error pages", async () => {
    isCloudMock.mockReturnValue(true);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    server.use(
      http.post(
        "https://api.example.com/api/v1/ingestions",
        () =>
          new HttpResponse("<html><body>upstream details</body></html>", {
            status: 502,
            headers: { "content-type": "text/html" },
          }),
      ),
    );

    const response = await POST(uploadRequest());

    expect(response.status).toBe(502);
    await expect(response.json()).resolves.toEqual({
      error: "Unable to start the import. Please try again.",
    });
  });

  it("returns a safe bad gateway response when the ingestion API connection fails", async () => {
    // Given
    isCloudMock.mockReturnValue(true);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("connect ECONNREFUSED api.internal")),
    );

    // When
    const response = await POST(uploadRequest());

    // Then
    expect(response.status).toBe(502);
    await expect(response.json()).resolves.toEqual({
      error: "Unable to start the import. Please try again.",
    });
  });

  it.each([
    [400, "invalid", "The report is not a valid Prowler OCSF finding report."],
    [
      402,
      "subscription_required",
      "A Prowler Cloud subscription is required to import findings.",
    ],
    [
      403,
      "permission_denied",
      "You do not have permission to import findings.",
    ],
    [
      413,
      "file_too_large",
      "The selected file exceeds the allowed upload size.",
    ],
    [
      429,
      "rate_limited",
      "Too many import requests. Please try again shortly.",
    ],
  ])(
    "maps known upstream rejection %i/%s to safe import guidance",
    async (status, code, message) => {
      isCloudMock.mockReturnValue(true);
      getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
      server.use(
        http.post("https://api.example.com/api/v1/ingestions", () =>
          HttpResponse.json(
            { errors: [{ code, detail: "internal implementation detail" }] },
            { status },
          ),
        ),
      );

      const response = await POST(uploadRequest());

      expect(response.status).toBe(status);
      await expect(response.json()).resolves.toEqual({ error: message });
    },
  );

  const STATUS_TIER_REJECTIONS = [
    [400, "The report is not a valid Prowler OCSF finding report."],
    [402, "A Prowler Cloud subscription is required to import findings."],
    [403, "You do not have permission to import findings."],
    [413, "The selected file exceeds the allowed upload size."],
    [429, "Too many import requests. Please try again shortly."],
  ] as const;

  it.each(STATUS_TIER_REJECTIONS)(
    "maps a codeless upstream rejection to the %i status guidance",
    async (status, message) => {
      isCloudMock.mockReturnValue(true);
      getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
      server.use(
        http.post("https://api.example.com/api/v1/ingestions", () =>
          HttpResponse.json(
            { detail: "internal implementation detail" },
            { status },
          ),
        ),
      );

      const response = await POST(uploadRequest());

      expect(response.status).toBe(status);
      await expect(response.json()).resolves.toEqual({ error: message });
    },
  );

  it.each(STATUS_TIER_REJECTIONS)(
    "falls through an unrecognized error code to the %i status guidance",
    async (status, message) => {
      isCloudMock.mockReturnValue(true);
      getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
      server.use(
        http.post("https://api.example.com/api/v1/ingestions", () =>
          HttpResponse.json(
            {
              errors: [
                {
                  code: "invalid_findings",
                  detail: "internal implementation detail",
                },
              ],
            },
            { status },
          ),
        ),
      );

      const response = await POST(uploadRequest());

      expect(response.status).toBe(status);
      await expect(response.json()).resolves.toEqual({ error: message });
    },
  );

  // An empty id parses into a trackable-looking job whose poll URL,
  // `/api/ingestions/`, matches no route: a created import reads as a failure.
  it.each([
    ["no job identifier", { attributes: { status: "pending" } }],
    ["an empty job identifier", { id: "", attributes: { status: "pending" } }],
  ])("refuses an accepted response with %s", async (_shape, data) => {
    isCloudMock.mockReturnValue(true);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    server.use(
      http.post("https://api.example.com/api/v1/ingestions", () =>
        HttpResponse.json({ data }),
      ),
    );

    const response = await POST(uploadRequest());

    expect(response.status).toBe(502);
    await expect(response.json()).resolves.toEqual({
      error: "Unable to start the import. Please try again.",
    });
  });

  it("rejects accepted responses that cannot start a trackable ingestion", async () => {
    isCloudMock.mockReturnValue(true);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    server.use(
      http.post("https://api.example.com/api/v1/ingestions", () =>
        HttpResponse.json({ data: { id: "ingestion-123", attributes: {} } }),
      ),
    );

    const response = await POST(uploadRequest());

    expect(response.status).toBe(502);
    await expect(response.json()).resolves.toEqual({
      error: "Unable to start the import. Please try again.",
    });
  });
});
