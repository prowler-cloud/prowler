import { describe, expect, it } from "vitest";

import {
  REGISTRY_ENDPOINT,
  REGISTRY_FAILURE,
  REGISTRY_SUBMISSION,
} from "@/types/registry";

import {
  adaptRegistryCredentialStatus,
  classifyRegistryFailure,
  collectCompleteRegistryCatalog,
  parseRegistryCredentialSubmission,
} from "./registry.adapter";

const credentialPayload = {
  data: {
    attributes: {
      configured: true,
      is_valid: true,
      scopes: ["catalog:read"],
      last_validated_at: "2026-03-20T12:00:00Z",
      validation_status: "valid",
      validation_pending: false,
      key: "registry-secret-value",
      masked_key: "reg_***",
      pending_key: "queued-secret",
      arbitrary_backend_detail: "do not expose",
    },
  },
};

const activeCredential = adaptRegistryCredentialStatus(credentialPayload);
const jsonError = (status: number, code: string) =>
  new Response(
    JSON.stringify({ errors: [{ code, detail: "private detail" }] }),
    {
      status,
    },
  );

describe("Registry adapter", () => {
  it("maps only documented non-secret credential status fields", () => {
    // Given
    const malformedPayload = { data: { attributes: { configured: true } } };

    // When
    const status = adaptRegistryCredentialStatus(credentialPayload);

    // Then
    expect(status).toEqual({
      configured: true,
      isValid: true,
      scopes: ["catalog:read"],
      lastValidatedAt: "2026-03-20T12:00:00Z",
      validationStatus: "valid",
      validationPending: false,
    });
    expect(adaptRegistryCredentialStatus(malformedPayload)).toBeNull();
  });

  it("normalizes an absent credential status with nullable validation fields", () => {
    // Given
    const absentCredentialPayload = {
      data: {
        attributes: {
          configured: false,
          is_valid: false,
          scopes: [],
          last_validated_at: null,
          validation_status: null,
          validation_pending: false,
        },
      },
    };

    // When
    const status = adaptRegistryCredentialStatus(absentCredentialPayload);

    // Then
    expect(status).toEqual({
      configured: false,
      isValid: false,
      scopes: [],
      lastValidatedAt: undefined,
      validationStatus: undefined,
      validationPending: false,
    });
  });

  it("accepts only a matching 202 task and fixed Content-Location path", async () => {
    // Given
    const response = new Response(
      JSON.stringify({ data: { type: "tasks", id: "task-123" } }),
      {
        status: 202,
        headers: { "Content-Location": "/api/v1/tasks/task-123" },
      },
    );

    // When
    const result = await parseRegistryCredentialSubmission(response);

    // Then
    expect(result).toEqual({
      status: REGISTRY_SUBMISSION.PENDING,
      taskId: "task-123",
    });
  });

  it("rejects a non-202 response or a mismatched task location", async () => {
    // Given
    const task = JSON.stringify({ data: { type: "tasks", id: "task-123" } });
    const wrongStatus = new Response(task, { status: 201 });
    const wrongLocation = new Response(task, {
      status: 202,
      headers: { "Content-Location": "/api/v1/tasks/other" },
    });

    // When
    const results = await Promise.all([
      parseRegistryCredentialSubmission(wrongStatus),
      parseRegistryCredentialSubmission(wrongLocation),
    ]);

    // Then
    expect(results).toEqual([
      { status: REGISTRY_SUBMISSION.ERROR },
      { status: REGISTRY_SUBMISSION.ERROR },
    ]);
  });

  it("classifies every Registry 401 or 403 as access denied first", async () => {
    // Given
    const responses = [
      [401, REGISTRY_ENDPOINT.CREDENTIAL],
      [403, REGISTRY_ENDPOINT.MUTATION],
      [403, REGISTRY_ENDPOINT.PROVIDERS],
    ] as const;

    // When
    const results = await Promise.all(
      responses.map(([status, endpoint]) =>
        classifyRegistryFailure(
          jsonError(status, "registry_key_rejected"),
          endpoint,
          activeCredential,
        ),
      ),
    );

    // Then
    expect(results).toEqual([
      { status: REGISTRY_FAILURE.ACCESS_DENIED },
      { status: REGISTRY_FAILURE.ACCESS_DENIED },
      { status: REGISTRY_FAILURE.ACCESS_DENIED },
    ]);
  });

  it("maps only a 409 with an authoritative no-active credential to onboarding", async () => {
    // Given
    const noCredential = adaptRegistryCredentialStatus({
      data: {
        attributes: {
          configured: false,
          is_valid: false,
          scopes: [],
          validation_pending: false,
        },
      },
    });

    // When
    const results = await Promise.all(
      [noCredential, null].map((credential) =>
        classifyRegistryFailure(
          new Response(null, { status: 409 }),
          REGISTRY_ENDPOINT.AVAILABLE_ARTIFACTS,
          credential,
        ),
      ),
    );

    // Then
    expect(results).toEqual([
      { status: REGISTRY_FAILURE.ONBOARDING },
      { status: REGISTRY_FAILURE.ERROR },
    ]);
  });

  it("maps only exact documented 502 and 503 status-code pairs", async () => {
    // Given
    const rejected = jsonError(502, "registry_key_rejected");
    const unavailable = jsonError(503, "registry_unavailable");

    // When
    const results = await Promise.all([
      classifyRegistryFailure(
        rejected,
        REGISTRY_ENDPOINT.PROVIDERS,
        activeCredential,
      ),
      classifyRegistryFailure(
        unavailable,
        REGISTRY_ENDPOINT.AVAILABLE_ARTIFACTS,
        activeCredential,
      ),
    ]);

    // Then
    expect(results).toEqual([
      { status: REGISTRY_FAILURE.RECONNECT },
      { status: REGISTRY_FAILURE.UNAVAILABLE },
    ]);
  });

  it("keeps wrong, malformed, and unrelated failures generic", async () => {
    // Given
    const malformed = new Response("<html>key=private</html>", { status: 503 });

    // When
    const results = await Promise.all([
      classifyRegistryFailure(
        jsonError(502, "other_error"),
        REGISTRY_ENDPOINT.PROVIDERS,
        activeCredential,
      ),
      classifyRegistryFailure(
        jsonError(502, "registry_unavailable"),
        REGISTRY_ENDPOINT.PROVIDERS,
        activeCredential,
      ),
      classifyRegistryFailure(
        malformed,
        REGISTRY_ENDPOINT.PROVIDERS,
        activeCredential,
      ),
    ]);

    // Then
    expect(results).toEqual([
      { status: REGISTRY_FAILURE.ERROR },
      { status: REGISTRY_FAILURE.ERROR },
      { status: REGISTRY_FAILURE.ERROR },
    ]);
  });

  it("degrades a non-terminal empty first catalog page", async () => {
    // Given
    const document = (page: number) => ({
      data: [],
      meta: { pagination: { page, pages: 2, count: 0 } },
    });

    // When
    const result = await collectCompleteRegistryCatalog(async (page) =>
      document(page),
    );

    // Then
    expect(result).toEqual({
      status: "incomplete",
      reason: "invalid_page",
      collectedCount: 0,
    });
  });

  it("accepts a terminal empty first catalog page", async () => {
    // Given
    const document = {
      data: [],
      meta: { pagination: { page: 1, pages: 1, count: 0 } },
    };

    // When
    const result = await collectCompleteRegistryCatalog(async () => document);

    // Then
    expect(result).toEqual({ status: "complete", artifacts: [] });
  });

  it("reads optional owner logo URLs tolerantly", async () => {
    // Given
    const document = {
      data: [
        {
          type: "registry-artifacts",
          id: "core",
          attributes: {
            owners: [
              {
                type: "organization",
                name: "Prowler",
                logo_url: "https://cdn.example/prowler.png",
              },
              { type: "user", name: "Ada" },
              { type: "user", name: "Blank", logo_url: "   " },
            ],
          },
        },
      ],
      meta: { pagination: { page: 1, pages: 1, count: 1 } },
    };

    // When
    const result = await collectCompleteRegistryCatalog(async () => document);

    // Then
    expect(result).toMatchObject({
      status: "complete",
      artifacts: [
        {
          normalizedName: "core",
          owners: [
            {
              type: "organization",
              name: "Prowler",
              logoUrl: "https://cdn.example/prowler.png",
            },
            { type: "user", name: "Ada", logoUrl: undefined },
            { type: "user", name: "Blank", logoUrl: undefined },
          ],
        },
      ],
    });
  });

  it("traverses, merges, and degrades unsafe catalog data", async () => {
    // Given
    // prettier-ignore
    const resource = (id: string, attributes: Record<string, unknown> = {}) => ({ type: "registry-artifacts", id, attributes });
    // prettier-ignore
    const document = (page: number, pages: number, count: number, data: unknown[]) => ({ data, meta: { pagination: { page, pages, count } } });
    const requests: Array<[number, string | null, string | null]> = [];

    // When
    // prettier-ignore
    const complete = await collectCompleteRegistryCatalog(async (page, query) => { requests.push([page, query.get("page[number]"), query.get("page[size]")]); return page === 1 ? document(1, 2, 3, [resource("core", { name: "Core", providers: ["AWS"], is_verified: true, version_count: 1, total_downloads: 2, owners: [{ type: "organization", name: "Prowler" }] }), resource("zeta")]) : document(2, 2, 3, [resource("core", { description: "Registry core", latest_version: "2.0.0", providers: ["gcp"], is_official: true, has_checks: true, version_count: 3, total_downloads: 8 })]); });
    // prettier-ignore
    const limits = await Promise.all([999, 1000, 1001].map(async (pages) => { let requests = 0; const result = await collectCompleteRegistryCatalog(async (page) => { requests += 1; return document(page, pages, pages, [resource(`item-${page}`)]); }); return [pages, requests, result] as const; }));
    // prettier-ignore
    const failures = await Promise.all([collectCompleteRegistryCatalog(async () => ({ data: {}, meta: {} })), collectCompleteRegistryCatalog(async () => document(1, 1, 2, [resource("one")])), collectCompleteRegistryCatalog(async (page) => document(page === 1 ? 1 : 1, 2, 2, [resource(`item-${page}`)])), collectCompleteRegistryCatalog(async (page) => document(page, page === 1 ? 2 : 3, 2, [resource(`item-${page}`)])), collectCompleteRegistryCatalog(async () => document(1, 1, 1, [resource("")])), collectCompleteRegistryCatalog(async (page) => document(page, 2, 2, [resource("duplicate", { name: page === 1 ? "One" : "Two" })])), collectCompleteRegistryCatalog(async (page) => { if (page === 2) throw new Error("offline"); return document(1, 2, 2, [resource("first")]); })]);

    // Then
    expect(requests).toEqual([
      [1, "1", "100"],
      [2, "2", "100"],
    ]);
    // prettier-ignore
    expect(complete).toMatchObject({ status: "complete", artifacts: [{ normalizedName: "core", name: "Core", description: "Registry core", latestVersion: "2.0.0", providers: ["aws", "gcp"], isVerified: true, isOfficial: true, hasChecks: true, versionCount: 3, totalDownloads: 8, owners: [{ type: "organization", name: "Prowler" }] }, { normalizedName: "zeta" }] });
    expect(limits.map(([pages, requests]) => [pages, requests])).toEqual([
      [999, 999],
      [1000, 1000],
      [1001, 1],
    ]);
    expect(limits[2]?.[2]).toEqual({
      status: "incomplete",
      reason: "guard_exhausted",
      collectedCount: 1,
    });
    expect(
      failures.map((result) =>
        result.status === "incomplete" ? result.reason : undefined,
      ),
    ).toEqual([
      "invalid_page",
      "count_mismatch",
      "invalid_page",
      "invalid_page",
      "invalid_resource",
      "conflicting_duplicate",
      "page_failed",
    ]);
    failures.forEach((result) =>
      expect(result).not.toHaveProperty("artifacts"),
    );
  });
});
