import { beforeEach, describe, expect, it, vi } from "vitest";

const { authMock, evaluateAccessMock, fetchMock, pollTaskUntilSettledMock } =
  vi.hoisted(() => ({
    authMock: vi.fn(),
    evaluateAccessMock: vi.fn(),
    fetchMock: vi.fn(),
    pollTaskUntilSettledMock: vi.fn(),
  }));

vi.mock("@/auth.config", () => ({ auth: authMock }));
vi.mock("@/lib", () => ({ apiBaseUrl: "https://api.test/api/v1" }));
vi.mock("@/actions/task/poll", () => ({
  pollTaskUntilSettled: pollTaskUntilSettledMock,
}));
vi.mock("@/lib/registry/access.server", () => ({
  evaluateRegistryAccess: evaluateAccessMock,
}));

import {
  addRegistryArtifact,
  disconnectRegistryCredential,
  getRegistryBootstrap,
  refreshRegistryCollections,
  removeRegistryArtifact,
  refreshRegistryCredential,
  submitRegistryCredential,
} from "./registry";

const activeCredential = {
  configured: true,
  isValid: true,
  scopes: ["catalog:read"],
  validationPending: false,
};
const noCredential = {
  configured: false,
  isValid: false,
  scopes: [],
  validationPending: false,
};
const pendingCredential = {
  configured: true,
  isValid: false,
  scopes: [],
  validationPending: true,
};

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/vnd.api+json" },
  });
const credentialResponse = (credential = activeCredential) =>
  jsonResponse({
    data: {
      attributes: {
        configured: credential.configured,
        is_valid: credential.isValid,
        scopes: credential.scopes,
        validation_pending: credential.validationPending,
      },
    },
  });
const tenantArtifactsResponse = () =>
  jsonResponse({
    data: [
      {
        type: "registry-artifacts",
        id: "prowler-aws",
        attributes: {
          version_spec: "latest",
          inserted_at: "2026-03-20T12:00:00Z",
        },
      },
    ],
  });
const providersResponse = () => jsonResponse({ data: [] });
const catalogResponse = () =>
  jsonResponse({
    data: [
      {
        type: "registry-artifacts",
        id: "prowler-aws",
        attributes: { name: "Prowler AWS", providers: ["aws"] },
      },
    ],
    meta: { pagination: { page: 1, pages: 1, count: 1 } },
  });

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  authMock.mockResolvedValue({ accessToken: "access-token" });
  evaluateAccessMock.mockResolvedValue({ status: "eligible" });
  fetchMock.mockReset();
  pollTaskUntilSettledMock.mockReset();
});

describe("Registry guarded reads", () => {
  it("denies every Registry data action before any Registry endpoint call", async () => {
    // Given
    evaluateAccessMock.mockResolvedValue({ status: "ineligible" });
    const actions = [
      getRegistryBootstrap,
      refreshRegistryCredential,
      refreshRegistryCollections,
      () => submitRegistryCredential("registry-test-key"),
      disconnectRegistryCredential,
    ];

    // When
    const results = await Promise.all(actions.map((action) => action()));

    // Then
    expect(results).toEqual([
      { status: "access_denied" },
      { status: "access_denied" },
      { status: "access_denied" },
      { status: "access_denied" },
      { status: "access_denied" },
    ]);
    expect(evaluateAccessMock).toHaveBeenCalledTimes(5);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each(["unknown", "ineligible"])(
    "denies Registry reads without calls when access is %s",
    async (status) => {
      // Given
      evaluateAccessMock.mockResolvedValue({ status });

      // When
      const results = await Promise.all([
        getRegistryBootstrap(),
        refreshRegistryCredential(),
        refreshRegistryCollections(),
      ]);

      // Then
      expect(results).toEqual([
        { status: "access_denied" },
        { status: "access_denied" },
        { status: "access_denied" },
      ]);
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("bootstraps in credential, tenant-artifact, providers, then complete-catalog order", async () => {
    // Given
    fetchMock
      .mockResolvedValueOnce(credentialResponse())
      .mockResolvedValueOnce(tenantArtifactsResponse())
      .mockResolvedValueOnce(providersResponse())
      .mockResolvedValueOnce(catalogResponse());

    // When
    const result = await getRegistryBootstrap();

    // Then
    expect(result).not.toHaveProperty("leaseDurationMs");
    expect(result).toEqual({
      status: "ready",
      state: {
        status: "ready",
        credential: activeCredential,
        catalog: {
          status: "complete",
          artifacts: [
            expect.objectContaining({ normalizedName: "prowler-aws" }),
          ],
        },
        tenantArtifacts: [
          {
            normalizedName: "prowler-aws",
            versionSpec: "latest",
            insertedAt: "2026-03-20T12:00:00Z",
          },
        ],
      },
    });
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "https://api.test/api/v1/registry/credential",
      "https://api.test/api/v1/registry/artifacts",
      "https://api.test/api/v1/registry/providers",
      "https://api.test/api/v1/registry/available-artifacts?page%5Bnumber%5D=1&page%5Bsize%5D=100",
    ]);
    fetchMock.mock.calls.forEach(([, options]) => {
      expect(options).toMatchObject({
        cache: "no-store",
        headers: {
          Accept: "application/vnd.api+json",
          Authorization: "Bearer access-token",
        },
      });
    });
  });

  it.each([
    [noCredential, "onboarding"],
    [pendingCredential, "validation_pending"],
  ] as const)(
    "blocks catalog bootstrap as %s credential is authoritative",
    async (credential, expectedStatus) => {
      // Given
      fetchMock
        .mockResolvedValueOnce(credentialResponse(credential))
        .mockResolvedValueOnce(tenantArtifactsResponse());

      // When
      const result = await getRegistryBootstrap();

      // Then
      expect(result).not.toHaveProperty("leaseDurationMs");
      expect(result).toEqual({
        status: "ready",
        state: {
          status: expectedStatus,
          credential,
          tenantArtifacts: [
            {
              normalizedName: "prowler-aws",
              versionSpec: "latest",
              insertedAt: "2026-03-20T12:00:00Z",
            },
          ],
        },
      });
      expect(fetchMock).toHaveBeenCalledTimes(2);
    },
  );

  it("returns only a non-secret status read after a fresh guard", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(credentialResponse());

    // When
    const result = await refreshRegistryCredential();

    // Then
    expect(result).toEqual({ status: "status", credential: activeCredential });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/api/v1/registry/credential",
      expect.objectContaining({ cache: "no-store" }),
    );
  });

  it("returns fresh complete collections without accepting a client lease", async () => {
    // Given
    fetchMock
      .mockResolvedValueOnce(providersResponse())
      .mockResolvedValueOnce(catalogResponse())
      .mockResolvedValueOnce(tenantArtifactsResponse());

    // When
    const result = await refreshRegistryCollections();

    // Then
    expect(result).toEqual({
      status: "complete",
      catalog: {
        status: "complete",
        artifacts: [expect.objectContaining({ normalizedName: "prowler-aws" })],
      },
      tenantArtifacts: [
        {
          normalizedName: "prowler-aws",
          versionSpec: "latest",
          insertedAt: "2026-03-20T12:00:00Z",
        },
      ],
    });
    expect(evaluateAccessMock).toHaveBeenCalledWith("access-token");
  });

  it("maps a discovery 409 to onboarding after an authoritative no-credential read", async () => {
    // Given
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ errors: [] }, 409))
      .mockResolvedValueOnce(credentialResponse(noCredential));

    // When
    const result = await refreshRegistryCollections();

    // Then
    expect(result).toEqual({ status: "onboarding" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("maps documented read recovery without exposing retained or partial catalog data", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ errors: [{ code: "registry_key_rejected" }] }, 502),
    );

    // When
    const reconnect = await refreshRegistryCollections();

    // Then
    expect(reconnect).toEqual({ status: "reconnect" });

    // Given
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ errors: [{ code: "registry_unavailable" }] }, 503),
    );

    // When
    const unavailable = await refreshRegistryCollections();

    // Then
    expect(unavailable).toEqual({ status: "unavailable" });
    expect(unavailable).not.toHaveProperty("catalog");

    // Given
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ errors: [{ code: "other_failure" }] }, 502),
    );

    // When
    const generic = await refreshRegistryCollections();

    // Then
    expect(generic).toEqual({ status: "error" });
  });

  it("maps Registry 401 and 403 to access denial before any recovery classification", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ errors: [{ code: "registry_key_rejected" }] }, 401),
    );

    // When
    const credential = await refreshRegistryCredential();

    // Then
    expect(credential).toEqual({ status: "access_denied" });

    // Given
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ errors: [{ code: "registry_unavailable" }] }, 403),
    );

    // When
    const collections = await refreshRegistryCollections();

    // Then
    expect(collections).toEqual({ status: "access_denied" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("rechecks access between separate actions after permission revocation", async () => {
    // Given
    evaluateAccessMock
      .mockResolvedValueOnce({ status: "eligible" })
      .mockResolvedValueOnce({ status: "ineligible" });
    fetchMock.mockResolvedValueOnce(credentialResponse());

    // When
    const first = await refreshRegistryCredential();
    const second = await refreshRegistryCollections();

    // Then
    expect(first).toEqual({ status: "status", credential: activeCredential });
    expect(second).toEqual({ status: "access_denied" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(evaluateAccessMock).toHaveBeenCalledTimes(2);
  });

  it("returns the accepted validation task immediately without server-side polling", async () => {
    // Given
    const key = "registry-test-key";
    fetchMock
      .mockResolvedValueOnce(credentialResponse(noCredential))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ data: { type: "tasks", id: "task-123" } }),
          {
            status: 202,
            headers: { "Content-Location": "/api/v1/tasks/task-123" },
          },
        ),
      );

    // When
    const result = await submitRegistryCredential(key);

    // Then
    expect(result).toEqual({
      status: "submitted",
      taskId: "task-123",
      priorConfigured: false,
    });
    expect(pollTaskUntilSettledMock).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://api.test/api/v1/registry/credential",
      expect.objectContaining({
        body: JSON.stringify({
          data: {
            type: "registry-credentials",
            attributes: { api_key: key },
          },
        }),
        cache: "no-store",
        method: "POST",
      }),
    );
    expect(JSON.stringify(result)).not.toContain(key);
  });

  it("marks an accepted replacement as superseding a configured credential", async () => {
    // Given
    fetchMock
      .mockResolvedValueOnce(credentialResponse(activeCredential))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ data: { type: "tasks", id: "task-456" } }),
          {
            status: 202,
            headers: { "Content-Location": "/api/v1/tasks/task-456" },
          },
        ),
      );

    // When
    const result = await submitRegistryCredential("registry-replacement-key");

    // Then
    expect(result).toEqual({
      status: "submitted",
      taskId: "task-456",
      priorConfigured: true,
    });
    expect(pollTaskUntilSettledMock).not.toHaveBeenCalled();
  });

  it("re-reads credential and preserves authoritative My artifacts after disconnect", async () => {
    // Given
    fetchMock
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(credentialResponse(noCredential))
      .mockResolvedValueOnce(tenantArtifactsResponse());

    // When
    const result = await disconnectRegistryCredential();

    // Then
    expect(result).toEqual({
      status: "disconnected",
      credential: noCredential,
      tenantArtifacts: [
        {
          normalizedName: "prowler-aws",
          versionSpec: "latest",
          insertedAt: "2026-03-20T12:00:00Z",
        },
      ],
    });
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "https://api.test/api/v1/registry/credential",
      "https://api.test/api/v1/registry/credential",
      "https://api.test/api/v1/registry/artifacts",
    ]);
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://api.test/api/v1/registry/credential",
      expect.objectContaining({ cache: "no-store", method: "DELETE" }),
    );
  });

  it("rejects a task-binding mismatch without returning the key or a task", async () => {
    // Given
    const key = "registry-test-key";
    fetchMock
      .mockResolvedValueOnce(credentialResponse(noCredential))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ data: { type: "tasks", id: "task-123" } }),
          {
            status: 202,
            headers: { "Content-Location": "/api/v1/tasks/other-task" },
          },
        ),
      );

    // When
    const result = await submitRegistryCredential(key);

    // Then
    expect(result).toEqual({ status: "error" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(pollTaskUntilSettledMock).not.toHaveBeenCalled();
    expect(JSON.stringify(result)).not.toContain(key);
  });

  it("rejects malformed accepted task data without a task identity", async () => {
    // Given
    fetchMock
      .mockResolvedValueOnce(credentialResponse(noCredential))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ data: { type: "not-a-task", id: "task-123" } }),
          {
            status: 202,
            headers: { "Content-Location": "/api/v1/tasks/task-123" },
          },
        ),
      );

    // When
    const result = await submitRegistryCredential("registry-test-key");

    // Then
    expect(result).toEqual({ status: "error" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result).not.toHaveProperty("taskId");
  });

  it("preserves an active credential after a rejected replacement", async () => {
    // Given
    const key = "registry-replacement-key";
    fetchMock
      .mockResolvedValueOnce(credentialResponse(activeCredential))
      .mockResolvedValueOnce(jsonResponse({ errors: [] }, 500));

    // When
    const result = await submitRegistryCredential(key);

    // Then
    expect(result).toEqual({
      status: "replacement_failed",
      credential: activeCredential,
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(JSON.stringify(result)).not.toContain(key);
  });

  it("handles action authorization failures safely", async () => {
    // Given
    fetchMock
      .mockResolvedValueOnce(credentialResponse(noCredential))
      .mockResolvedValueOnce(jsonResponse({ errors: [] }, 401))
      .mockResolvedValueOnce(jsonResponse({ errors: [] }, 403));

    // When
    const rejected = await submitRegistryCredential("registry-test-key");
    const disconnected = await disconnectRegistryCredential();

    // Then
    expect(rejected).toEqual({ status: "access_denied" });
    expect(disconnected).toEqual({ status: "access_denied" });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("returns an accepted Add task without reading My artifacts", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ data: { type: "tasks", id: "artifact-task" } }),
        {
          status: 202,
          headers: { "Content-Location": "/api/v1/tasks/artifact-task" },
        },
      ),
    );

    // When
    const result = await addRegistryArtifact({
      normalizedName: "later-guard",
      versionSpec: " 2.0.0 ",
    });

    // Then
    expect(result).toEqual({ status: "submitted", taskId: "artifact-task" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://api.test/api/v1/registry/artifacts",
      expect.objectContaining({
        body: JSON.stringify({
          data: {
            type: "registry-artifacts",
            attributes: {
              normalized_name: "later-guard",
              version_spec: "2.0.0",
            },
          },
        }),
        cache: "no-store",
        method: "POST",
      }),
    );
  });

  it("defaults Add to latest", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ data: { type: "tasks", id: "artifact-task" } }),
        {
          status: 202,
          headers: { "Content-Location": "/api/v1/tasks/artifact-task" },
        },
      ),
    );

    // When
    const result = await addRegistryArtifact({ normalizedName: "later-guard" });

    // Then
    expect(result).toEqual({ status: "submitted", taskId: "artifact-task" });
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://api.test/api/v1/registry/artifacts",
      expect.objectContaining({
        body: JSON.stringify({
          data: {
            type: "registry-artifacts",
            attributes: {
              normalized_name: "later-guard",
              version_spec: "latest",
            },
          },
        }),
      }),
    );
  });

  it("rejects invalid accepted task bindings without reading My artifacts", async () => {
    // Given
    const document = JSON.stringify({
      data: { type: "tasks", id: "artifact-task" },
    });
    fetchMock
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: { type: "tasks" } }), {
          status: 202,
          headers: { "Content-Location": "/api/v1/tasks/artifact-task" },
        }),
      )
      .mockResolvedValueOnce(new Response(document, { status: 202 }))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ data: { type: "other", id: "artifact-task" } }),
          {
            status: 202,
            headers: { "Content-Location": "/api/v1/tasks/artifact-task" },
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(document, {
          status: 202,
          headers: { "Content-Location": "/api/v1/tasks/other" },
        }),
      );

    // When
    const outcomes = await Promise.all(
      ["missing-id", "missing-location", "wrong-type", "wrong-location"].map(
        () => addRegistryArtifact({ normalizedName: "later-guard" }),
      ),
    );

    // Then
    expect(outcomes).toEqual(Array(4).fill({ status: "error" }));
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it("keeps a missing Registry credential synchronous", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(jsonResponse({ errors: [] }, 409));

    // When
    const outcome = await addRegistryArtifact({
      normalizedName: "later-guard",
    });

    // Then
    expect(outcome).toEqual({ status: "onboarding" });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it.each([
    ["registry_artifact_not_found", "This artifact is no longer available."],
    ["version_yanked", "This version is no longer available."],
    [
      "version_not_verified",
      "This version is not verified and cannot be added.",
    ],
    ["version_not_processed", "This version is not ready to add yet."],
    ["version_not_found", "This version is not available."],
    ["no_installable_version", "No available version can be added."],
  ])("keeps membership unchanged for %s", async (code, message) => {
    // Given
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        { errors: [{ code }] },
        code === "registry_artifact_not_found" ? 404 : 400,
      ),
    );

    // When
    const result = await addRegistryArtifact({
      normalizedName: "later-guard",
      versionSpec: "2.0.0",
    });

    // Then
    expect(result).toEqual({ status: "refused", message });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("encodes the deletion identity and confirms Remove after an absent refresh", async () => {
    // Given
    fetchMock
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(jsonResponse({ data: [] }));

    // When
    const result = await removeRegistryArtifact("guard/with space");

    // Then
    expect(result).toEqual({ status: "confirmed", tenantArtifacts: [] });
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://api.test/api/v1/registry/artifacts/guard%2Fwith%20space",
      expect.objectContaining({ cache: "no-store", method: "DELETE" }),
    );
  });

  it.each([
    [
      "Add",
      () => addRegistryArtifact({ normalizedName: "later-guard" }),
      { data: [] },
      { status: "error" },
      1,
    ],
    [
      "Remove",
      () => removeRegistryArtifact("later-guard"),
      {
        data: [
          {
            type: "registry-artifacts",
            id: "later-guard",
            attributes: { version_spec: "latest" },
          },
        ],
      },
      { status: "refresh_failed" },
      2,
    ],
  ])(
    "keeps membership unchanged when %s refresh contradicts acceptance",
    async (_name, mutate, refreshedArtifacts, expected, calls) => {
      // Given
      fetchMock
        .mockResolvedValueOnce(new Response(null, { status: 204 }))
        .mockResolvedValueOnce(jsonResponse(refreshedArtifacts));

      // When
      const result = await mutate();

      // Then
      expect(result).toEqual(expected);
      expect(fetchMock).toHaveBeenCalledTimes(calls);
    },
  );
});
