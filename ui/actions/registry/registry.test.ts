import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  authMock,
  evaluateAccessMock,
  evaluateProviderAccessMock,
  fetchMock,
  pollTaskUntilSettledMock,
} = vi.hoisted(() => ({
  authMock: vi.fn(),
  evaluateAccessMock: vi.fn(),
  evaluateProviderAccessMock: vi.fn(),
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
  evaluateRegistryProviderAccess: evaluateProviderAccessMock,
}));

import {
  addRegistryArtifact,
  confirmRegistryArtifactAddition,
  disconnectRegistryCredential,
  getRegistryBootstrap,
  getInstalledRegistryProviderOptions,
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
  evaluateProviderAccessMock.mockResolvedValue({ status: "eligible" });
  fetchMock.mockReset();
  pollTaskUntilSettledMock.mockReset();
});

function mockRequestDeadlines() {
  // Native AbortSignal.timeout uses real timers; drive it with the test clock.
  vi.spyOn(AbortSignal, "timeout").mockImplementation((milliseconds) => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), milliseconds);
    return controller.signal;
  });
}

describe("installed Registry provider discovery", () => {
  function mockDiscovery({
    emptyMetadata = false,
    failedEndpoint,
    failureStatus = 500,
    failureBody = {},
  }: {
    emptyMetadata?: boolean;
    failedEndpoint?: string;
    failureStatus?: number;
    failureBody?: unknown;
  } = {}) {
    fetchMock.mockImplementation((url: string) => {
      const endpoint = new URL(url).pathname.split("/").pop();
      if (endpoint === failedEndpoint)
        return jsonResponse(failureBody, failureStatus);
      if (endpoint === "available-artifacts")
        return jsonResponse({
          data: [
            {
              type: "registry-artifacts",
              id: "acme-package",
              attributes: {
                name: "Acme package",
                providers: ["acme"],
                has_provider: true,
              },
            },
          ],
          meta: { pagination: { page: 1, pages: 1, count: 1 } },
        });
      if (endpoint === "artifacts")
        return jsonResponse({
          data: [
            {
              type: "registry-artifacts",
              id: "acme-package",
              attributes: { version_spec: "latest" },
            },
          ],
        });
      if (endpoint === "providers")
        return jsonResponse({
          data: emptyMetadata
            ? []
            : [
                {
                  id: "acme",
                  attributes: {
                    name: "Acme Cloud",
                    logo_url: "https://media.registry.test/acme.svg",
                  },
                },
              ],
        });
      throw new Error(`Unexpected endpoint: ${endpoint}`);
    });
  }

  it("joins catalog declarations, installed membership and provider metadata", async () => {
    mockDiscovery();
    expect(await getInstalledRegistryProviderOptions()).toEqual({
      status: "ready",
      options: [
        {
          type: "acme",
          label: "Acme Cloud",
          logoUrl: "https://media.registry.test/acme.svg",
        },
      ],
    });
  });

  it("allows installed-provider discovery without Registry management access", async () => {
    // Given
    mockDiscovery({ emptyMetadata: true });
    evaluateAccessMock.mockResolvedValue({ status: "ineligible" });
    // When / Then
    expect(await getInstalledRegistryProviderOptions()).toEqual({
      status: "ready",
      options: [{ type: "acme", label: "Acme package" }],
    });
    expect(evaluateProviderAccessMock).toHaveBeenCalledWith("access-token");
    expect(evaluateAccessMock).not.toHaveBeenCalled();
  });

  it.each([
    ["ineligible", "access_denied"],
    ["unknown", "unknown"],
  ] as const)(
    "maps installed-provider access %s to %s",
    async (status, expectedStatus) => {
      // Given
      evaluateProviderAccessMock.mockResolvedValue({ status });

      // When
      const result = await getInstalledRegistryProviderOptions();

      // Then
      expect(result).toEqual({ status: expectedStatus });
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("uses the declared provider and artifact name when metadata is empty", async () => {
    mockDiscovery({ emptyMetadata: true });
    expect(await getInstalledRegistryProviderOptions()).toEqual({
      status: "ready",
      options: [{ type: "acme", label: "Acme package" }],
    });
  });

  it.each(["available-artifacts", "artifacts", "providers"])(
    "returns an error when the %s read fails",
    async (failedEndpoint) => {
      mockDiscovery({ failedEndpoint });
      expect(await getInstalledRegistryProviderOptions()).toEqual({
        status: "error",
      });
    },
  );

  it.each(["available-artifacts", "artifacts", "providers"])(
    "preserves access denial from the %s read",
    async (failedEndpoint) => {
      mockDiscovery({ failedEndpoint, failureStatus: 403 });
      expect(await getInstalledRegistryProviderOptions()).toEqual({
        status: "access_denied",
      });
    },
  );

  it.each(["available-artifacts", "artifacts", "providers"])(
    "hides Registry when the backend has it disabled and %s answers 404",
    async (failedEndpoint) => {
      mockDiscovery({ failedEndpoint, failureStatus: 404 });
      expect(await getInstalledRegistryProviderOptions()).toEqual({
        status: "access_denied",
      });
    },
  );

  it.each(["available-artifacts", "providers"])(
    "keeps Registry visible when an enabled backend answers 404 for a missing %s page",
    async (failedEndpoint) => {
      mockDiscovery({
        failedEndpoint,
        failureStatus: 404,
        failureBody: {
          errors: [{ status: "404", code: "registry_page_not_found" }],
        },
      });
      expect(await getInstalledRegistryProviderOptions()).toEqual({
        status: "error",
      });
    },
  );
});

describe("Registry guarded reads", () => {
  it("recovers when a Registry read stalls", async () => {
    // Given: the upstream responds only when its request is aborted.
    vi.useFakeTimers();
    try {
      mockRequestDeadlines();
      fetchMock.mockImplementation(
        (_url, init?: RequestInit) =>
          new Promise((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () =>
              reject(init.signal?.reason),
            );
          }),
      );
      const settled = vi.fn();

      // When
      void refreshRegistryCredential().then(settled);
      await vi.advanceTimersByTimeAsync(30_000);

      // Then
      expect(settled).toHaveBeenCalledWith({ status: "error" });
    } finally {
      vi.useRealTimers();
    }
  });

  it.each([
    [
      "credential submission",
      () => submitRegistryCredential("registry-test-key"),
    ],
    ["credential disconnection", disconnectRegistryCredential],
    [
      "artifact addition",
      () => addRegistryArtifact({ normalizedName: "external-package" }),
    ],
    ["artifact removal", () => removeRegistryArtifact("external-package")],
  ])("recovers when %s stalls", async (_name, action) => {
    // Given: prerequisite reads succeed, but the mutation never responds.
    vi.useFakeTimers();
    try {
      mockRequestDeadlines();
      fetchMock.mockImplementation((url: string, init?: RequestInit) => {
        if (init?.method === "POST" || init?.method === "DELETE") {
          return new Promise((_resolve, reject) => {
            init.signal?.addEventListener("abort", () =>
              reject(init.signal?.reason),
            );
          });
        }
        if (url.includes("available-artifacts")) {
          return Promise.resolve(
            jsonResponse({
              data: [
                {
                  type: "registry-artifacts",
                  id: "external-package",
                  attributes: {
                    has_provider: true,
                    is_builtin: false,
                    is_installable: true,
                  },
                },
              ],
              meta: { pagination: { page: 1, pages: 1, count: 1 } },
            }),
          );
        }
        return Promise.resolve(credentialResponse(noCredential));
      });
      const settled = vi.fn();

      // When
      void action().then(settled);
      await vi.advanceTimersByTimeAsync(30_000);

      // Then
      expect(settled).toHaveBeenCalledWith({ status: "error" });
    } finally {
      vi.useRealTimers();
    }
  });

  it("denies Registry management actions before any Registry endpoint call", async () => {
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
    expect(results).toEqual(actions.map(() => ({ status: "access_denied" })));
    expect(evaluateAccessMock).toHaveBeenCalledTimes(actions.length);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each(["unknown", "ineligible"])(
    "does not fetch Registry collections when access is %s",
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
        { status: status === "unknown" ? "error" : "access_denied" },
      ]);
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("bootstraps in credential, tenant-artifact, then complete-catalog order", async () => {
    // Given
    fetchMock
      .mockResolvedValueOnce(credentialResponse())
      .mockResolvedValueOnce(tenantArtifactsResponse())
      .mockResolvedValueOnce(catalogResponse());

    // When
    const result = await getRegistryBootstrap();

    // Then
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
            extendsProviderSlugs: [],
            insertedAt: "2026-03-20T12:00:00Z",
          },
        ],
      },
    });
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "https://api.test/api/v1/registry/credential",
      "https://api.test/api/v1/registry/artifacts",
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
      expect(result).toEqual({
        status: "ready",
        state: {
          status: expectedStatus,
          credential,
          tenantArtifacts: [
            {
              normalizedName: "prowler-aws",
              versionSpec: "latest",
              extendsProviderSlugs: [],
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

  it("returns fresh complete collections", async () => {
    // Given
    fetchMock
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
          extendsProviderSlugs: [],
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

  it("keeps a transient access check failure retryable when refreshing collections", async () => {
    // Given: the API cannot answer the permission check during a transient outage.
    evaluateAccessMock.mockResolvedValueOnce({ status: "unknown" });

    // When / Then: preserve the current page instead of treating the outage as revocation.
    expect(await refreshRegistryCollections()).toEqual({ status: "error" });
    expect(fetchMock).not.toHaveBeenCalled();
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
    const key = "  registry-test-key  ";
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
            attributes: { api_key: key.trim() },
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
          extendsProviderSlugs: [],
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
});

const installCatalogMock = vi.fn();
describe("Registry artifact mutations", () => {
  beforeEach(() => {
    installCatalogMock.mockImplementation(() =>
      jsonResponse({
        data: [
          {
            type: "registry-available-artifacts",
            id: "later-guard",
            attributes: {
              has_provider: true,
              is_builtin: false,
              is_installable: true,
              providers: ["acme"],
            },
          },
        ],
        meta: { pagination: { page: 1, pages: 1, count: 1 } },
      }),
    );
    vi.stubGlobal("fetch", (url: string, options?: RequestInit) =>
      url.includes("/available-artifacts")
        ? installCatalogMock(url, options)
        : fetchMock(url, options),
    );
  });

  it.each([
    [
      {
        has_checks: true,
        is_installable: false,
        not_installable_reason: "checks_target_is_not_builtin",
      },
      "Its checks are written for a provider this deployment does not ship.",
    ],
    [
      {
        has_checks: true,
        is_installable: false,
        not_installable_reason: "a_code_from_a_newer_api",
      },
      "This artifact cannot be installed in this deployment.",
    ],
    [
      { has_provider: true, is_builtin: false },
      "This artifact cannot be installed in this deployment.",
    ],
  ])(
    "refuses what the API says cannot be installed before POST: %j",
    async (attributes, message) => {
      // Given
      installCatalogMock.mockImplementation(() =>
        jsonResponse({
          data: [
            {
              type: "registry-available-artifacts",
              id: "later-guard",
              attributes,
            },
          ],
          meta: { pagination: { page: 1, pages: 1, count: 1 } },
        }),
      );
      // When
      const result = await addRegistryArtifact({
        normalizedName: "later-guard",
      });
      // Then
      expect(result).toEqual({ status: "refused", message });
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("submits a checks artifact that defines no provider once the API calls it installable", async () => {
    // Given
    installCatalogMock.mockImplementation(() =>
      jsonResponse({
        data: [
          {
            type: "registry-available-artifacts",
            id: "later-guard",
            attributes: {
              has_provider: false,
              has_checks: true,
              is_installable: true,
              providers: ["aws"],
            },
          },
        ],
        meta: { pagination: { page: 1, pages: 1, count: 1 } },
      }),
    );
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ data: { type: "tasks", id: "task-1" } }), {
        status: 202,
        headers: { "Content-Location": "/api/v1/tasks/task-1" },
      }),
    );

    // When
    const result = await addRegistryArtifact({ normalizedName: "later-guard" });

    // Then
    expect(result).toEqual({ status: "submitted", taskId: "task-1" });
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

  it.each([
    ["registry_artifact_in_use", "in_use"],
    ["registry_artifact_busy", "busy"],
  ])(
    "tells a Remove 409 %s apart as %s without refreshing membership",
    async (code, expected) => {
      // Given
      fetchMock.mockResolvedValueOnce(
        jsonResponse({ errors: [{ code }] }, 409),
      );

      // When
      const result = await removeRegistryArtifact("aws-guard");

      // Then
      expect(result).toEqual({ status: expected });
      expect(fetchMock).toHaveBeenCalledTimes(1);
    },
  );

  it("never asks someone to delete providers over a Remove 409 it cannot identify", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 409 }));

    // When
    const result = await removeRegistryArtifact("aws-guard");

    // Then
    expect(result).toEqual({ status: "error" });
  });

  it.each([
    [401, "access_denied"],
    [403, "access_denied"],
    [400, "error"],
    [500, "error"],
  ])("preserves the Remove failure for HTTP %s", async (status, expected) => {
    // Given
    fetchMock.mockResolvedValueOnce(new Response(null, { status }));

    // When
    const result = await removeRegistryArtifact("aws-guard");

    // Then
    expect(result).toEqual({ status: expected });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("reports a Remove network failure without refreshing membership", async () => {
    // Given
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));

    // When
    const result = await removeRegistryArtifact("aws-guard");

    // Then
    expect(result).toEqual({ status: "error" });
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

  it.each(["1.0.0", null, undefined])(
    "does not confirm an update when the installed version is %j",
    async (resolvedVersion) => {
      // Given
      fetchMock.mockResolvedValueOnce(
        jsonResponse({
          data: [
            {
              type: "registry-artifacts",
              id: "template",
              attributes: {
                version_spec: "latest",
                resolved_version: resolvedVersion,
              },
            },
          ],
        }),
      );
      // When
      const result = await confirmRegistryArtifactAddition("template", "1.1.0");
      // Then
      expect(result).toEqual({ status: "refresh_failed" });
    },
  );

  it("confirms an update only after reading its resolved target version", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        data: [
          {
            type: "registry-artifacts",
            id: "template",
            attributes: { version_spec: "latest", resolved_version: "1.1.0" },
          },
        ],
      }),
    );
    // When / Then
    expect(
      await confirmRegistryArtifactAddition("template", "1.1.0"),
    ).toMatchObject({
      status: "confirmed",
      tenantArtifacts: [
        { normalizedName: "template", resolvedVersion: "1.1.0" },
      ],
    });
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
