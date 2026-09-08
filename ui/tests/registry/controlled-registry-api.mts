import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";

const port = 4300;
const taskId = "fixture-registry-validation-task";
const artifactTaskId = "fixture-registry-artifact-task";
const fixtureAccessToken = [
  base64UrlJson({ alg: "none", typ: "JWT" }),
  base64UrlJson({
    exp: 4_102_444_800,
    sub: "fixture-registry-user",
    tenant_id: "fixture-registry-tenant",
  }),
  "fixture-signature-not-a-secret",
].join(".");

type CredentialState = "active" | "onboarding" | "pending";
type DiscoveryMode = "error" | "ready" | "reconnect" | "unavailable";

const fixtureProviderId = "d4e71fb8-c657-4c1b-a6ea-92fe611b3431";
const fixtureSecretId = "e9d17da5-04d7-447b-a59d-8726794a6d55";
const fixtureScanId = "9b82e67d-513b-4c41-b981-9e559f920f40";
const fixtureConnectionTaskId = "2118a6a8-7795-4d70-822a-7256c837fd30";

interface FixtureState {
  holdArtifactTask: boolean;
  providerCreated: boolean;
  providerUid: string;
  providerAlias: string;
  secretSaved: boolean;
  connected: boolean;
  scanCreated: boolean;
  connectionReadCount: number;
  artifactEvents: string[];
  artifactReadCount: number;
  artifactSubmissionCount: number;
  artifactTaskNormalizedName?: string;
  artifactTaskReadCount: number;
  artifactTaskVersionSpec?: string;
  credentialAccepted: boolean;
  credentialReadCount: number;
  credentialState: CredentialState;
  discoveryMode: DiscoveryMode;
  hasCurrentAuthority: boolean;
  taskReadCount: number;
  tenantArtifacts: Map<string, string>;
}

const initialState = (): FixtureState => ({
  holdArtifactTask: false,
  providerCreated: false,
  providerUid: "",
  providerAlias: "",
  secretSaved: false,
  connected: false,
  scanCreated: false,
  connectionReadCount: 0,
  artifactEvents: [],
  artifactReadCount: 0,
  artifactSubmissionCount: 0,
  artifactTaskReadCount: 0,
  credentialAccepted: false,
  credentialReadCount: 0,
  credentialState: "onboarding",
  discoveryMode: "ready",
  hasCurrentAuthority: true,
  taskReadCount: 0,
  tenantArtifacts: new Map(),
});

let state = initialState();

const catalogPages = [
  [
    catalogArtifact("fixture-network-audit", {
      description: "Synthetic Registry fixture network audit",
      has_checks: true,
      has_provider: true,
      is_builtin: false,
      is_official: true,
      is_verified: true,
      latest_version: "1.2.3",
      name: "Fixture network audit",
      owner_logo_url:
        "https://media.registry.dev.prowler.com/fixture-owner.svg",
      owner_name: "Prowler Fixtures",
      owner_slug: "prowler-fixtures",
      owner_type: "organization",
      providers: ["fixturecloud"],
    }),
    catalogArtifact("fixture-built-in-provider", {
      description: "Synthetic Registry fixture built-in provider",
      has_provider: true,
      is_builtin: true,
      latest_version: "1.0.0",
      name: "Fixture built-in provider",
      providers: ["aws"],
    }),
    catalogArtifact("fixture-shared-policy", {
      description: "Synthetic Registry fixture shared policy",
      has_compliance: true,
      latest_version: "2.0.0",
      name: "Fixture shared policy",
      owner_name: "Community Fixtures",
      owner_slug: "community-fixtures",
      owner_type: "organization",
      providers: ["aws"],
    }),
  ],
  [
    catalogArtifact("fixture-shared-policy", {
      description: "Synthetic Registry fixture shared policy",
      has_compliance: true,
      latest_version: "2.0.0",
      name: "Fixture shared policy",
      providers: ["gcp"],
    }),
  ],
] as const;

const server = createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", "http://127.0.0.1");

  try {
    if (url.pathname.startsWith("/__fixture__/registry/")) {
      await handleFixtureControl(request, response, url.pathname);
      return;
    }

    await handleApiRequest(request, response, url);
  } catch {
    sendJson(response, 500, { errors: [{ code: "fixture_request_failed" }] });
  }
});

server.listen(port, "127.0.0.1");

async function handleFixtureControl(
  request: IncomingMessage,
  response: ServerResponse,
  pathname: string,
) {
  if (
    request.method !== "POST" &&
    pathname !== "/__fixture__/registry/snapshot"
  ) {
    sendJson(response, 405, { errors: [{ code: "method_not_allowed" }] });
    return;
  }

  if (pathname === "/__fixture__/registry/reset") {
    state = initialState();
    sendJson(response, 200, { ok: true });
    return;
  }

  if (pathname === "/__fixture__/registry/revoke-current-authority") {
    state.hasCurrentAuthority = false;
    sendJson(response, 200, { ok: true });
    return;
  }

  if (pathname === "/__fixture__/registry/artifact-task-hold") {
    const body = await readJson(request);
    state.holdArtifactTask = readStringField(body, "hold") === "true";
    sendJson(response, 200, { ok: true });
    return;
  }

  if (pathname === "/__fixture__/registry/discovery-mode") {
    const body = await readJson(request);
    const mode = readStringField(body, "mode");
    if (!mode || !["error", "reconnect", "unavailable"].includes(mode)) {
      sendJson(response, 400, { errors: [{ code: "invalid_fixture_mode" }] });
      return;
    }
    state.discoveryMode = mode as Exclude<DiscoveryMode, "ready">;
    sendJson(response, 200, { ok: true });
    return;
  }

  if (pathname === "/__fixture__/registry/snapshot") {
    sendJson(response, 200, {
      artifactEvents: state.artifactEvents,
      artifactReadCount: state.artifactReadCount,
      artifactSubmissionCount: state.artifactSubmissionCount,
      artifactTaskReadCount: state.artifactTaskReadCount,
      credentialAccepted: state.credentialAccepted,
      credentialReadCount: state.credentialReadCount,
      taskReadCount: state.taskReadCount,
      providerCreated: state.providerCreated,
      secretSaved: state.secretSaved,
      connected: state.connected,
      scanCreated: state.scanCreated,
    });
    return;
  }

  sendJson(response, 404, { errors: [{ code: "fixture_not_found" }] });
}

async function handleApiRequest(
  request: IncomingMessage,
  response: ServerResponse,
  url: URL,
) {
  const { method } = request;
  const { pathname } = url;

  if (method === "GET" && pathname === "/health") {
    sendJson(response, 200, { status: "ready" });
    return;
  }

  if (method === "POST" && pathname === "/api/v1/tokens") {
    sendJson(response, 200, tokenDocument());
    return;
  }

  if (method === "POST" && pathname === "/api/v1/tokens/refresh") {
    sendJson(response, 200, tokenDocument());
    return;
  }

  if (method === "GET" && pathname === "/api/v1/users/me") {
    sendJson(response, 200, currentUserDocument());
    return;
  }

  if (method === "GET" && pathname === "/api/v1/provider-groups") {
    sendJson(response, 200, { data: [] });
    return;
  }

  if (
    method === "GET" &&
    [
      "/api/v1/organizations",
      "/api/v1/scan-configurations",
      "/api/v1/schedules",
    ].includes(pathname)
  ) {
    sendJson(response, 200, collectionDocument([]));
    return;
  }
  if (method === "GET" && pathname === "/api/v1/providers") {
    sendJson(
      response,
      200,
      collectionDocument(state.providerCreated ? [providerResource()] : []),
    );
    return;
  }
  if (method === "POST" && pathname === "/api/v1/providers") {
    const body = await readJson(request);
    if (
      !state.tenantArtifacts.has("fixture-network-audit") ||
      state.providerCreated ||
      readNestedString(body, ["data", "attributes", "provider"]) !==
        "fixturecloud"
    ) {
      sendJson(response, 400, {
        errors: [{ detail: "Provider is unavailable or already exists." }],
      });
      return;
    }
    state.providerCreated = true;
    state.providerUid =
      readNestedString(body, ["data", "attributes", "uid"]) || "";
    state.providerAlias =
      readNestedString(body, ["data", "attributes", "alias"]) || "";
    sendJson(response, 201, { data: providerResource() });
    return;
  }
  if (
    method === "GET" &&
    pathname === `/api/v1/providers/${fixtureProviderId}`
  ) {
    sendJson(response, 200, { data: providerResource() });
    return;
  }
  if (
    method === "GET" &&
    pathname === "/api/v1/provider-schemas/fixturecloud"
  ) {
    sendJson(response, 200, {
      data: {
        id: "fixturecloud",
        type: "provider-schemas",
        attributes: {
          secret_types: {
            api_key: {
              type: "object",
              properties: {
                token: {
                  type: "string",
                  title: "API token",
                  format: "password",
                  writeOnly: true,
                },
              },
              required: ["token"],
            },
          },
        },
      },
    });
    return;
  }
  if (
    (method === "POST" && pathname === "/api/v1/providers/secrets") ||
    (method === "PATCH" &&
      pathname === `/api/v1/providers/secrets/${fixtureSecretId}`)
  ) {
    const body = await readJson(request);
    state.secretSaved =
      readNestedString(body, ["data", "attributes", "secret", "token"]) ===
        "fixture-provider-token-not-a-secret" &&
      readNestedString(body, ["data", "attributes", "secret_type"]) ===
        "api_key";
    sendJson(
      response,
      state.secretSaved ? 201 : 400,
      state.secretSaved
        ? { data: { id: fixtureSecretId, type: "provider-secrets" } }
        : { errors: [{ detail: "Invalid test credentials" }] },
    );
    return;
  }
  if (
    method === "POST" &&
    pathname === `/api/v1/providers/${fixtureProviderId}/connection`
  ) {
    state.connectionReadCount = 0;
    sendJson(response, 202, {
      data: { id: fixtureConnectionTaskId, type: "tasks" },
    });
    return;
  }
  if (
    method === "GET" &&
    pathname === `/api/v1/tasks/${fixtureConnectionTaskId}`
  ) {
    state.connectionReadCount += 1;
    const complete = state.connectionReadCount >= 2;
    state.connected = complete && state.secretSaved;
    sendJson(response, 200, {
      data: {
        id: fixtureConnectionTaskId,
        type: "tasks",
        attributes: {
          state: complete ? "completed" : "executing",
          result: complete ? { connected: state.connected, error: null } : null,
        },
      },
    });
    return;
  }
  if (method === "POST" && pathname === "/api/v1/scans") {
    if (!state.connected) {
      sendJson(response, 400, {
        errors: [{ detail: "Connect the provider first" }],
      });
      return;
    }
    state.scanCreated = true;
    sendJson(response, 201, { data: scanResource() });
    return;
  }
  if (method === "GET" && pathname === "/api/v1/scans") {
    const states = url.searchParams.get("filter[state__in]");
    const data =
      state.scanCreated && (!states || states.includes("completed"))
        ? [scanResource()]
        : [];
    sendJson(response, 200, {
      ...collectionDocument(data),
      included: state.providerCreated ? [providerResource()] : [],
    });
    return;
  }

  if (method === "GET" && pathname === "/api/v1/registry/credential") {
    state.credentialReadCount += 1;
    sendJson(response, 200, credentialDocument());
    return;
  }

  if (method === "POST" && pathname === "/api/v1/registry/credential") {
    const body = await readJson(request);
    state.credentialAccepted =
      readNestedString(body, ["data", "attributes", "api_key"]) ===
      "fixture-registry-key-not-a-secret";
    if (!state.credentialAccepted) {
      sendJson(response, 422, { errors: [{ code: "invalid_fixture_key" }] });
      return;
    }
    state.credentialState = "pending";
    state.taskReadCount = 0;
    sendJson(
      response,
      202,
      { data: { id: taskId, type: "tasks" } },
      { "Content-Location": `/api/v1/tasks/${taskId}` },
    );
    return;
  }

  if (method === "DELETE" && pathname === "/api/v1/registry/credential") {
    state.credentialState = "onboarding";
    sendJson(response, 204);
    return;
  }

  if (method === "GET" && pathname === `/api/v1/tasks/${taskId}`) {
    state.taskReadCount += 1;
    const complete = state.taskReadCount >= 2;
    if (complete) state.credentialState = "active";
    sendJson(response, 200, {
      data: {
        attributes: {
          state: complete ? "completed" : "executing",
          ...(complete ? { result: { stored: true, error: null } } : {}),
        },
        id: taskId,
        type: "tasks",
      },
    });
    return;
  }

  if (method === "GET" && pathname === "/api/v1/registry/artifacts") {
    state.artifactReadCount += 1;
    state.artifactEvents.push("authoritative-read");
    sendJson(response, 200, tenantArtifactsDocument());
    return;
  }

  if (method === "POST" && pathname === "/api/v1/registry/artifacts") {
    const body = bodyOrEmpty(await readJson(request));
    const normalizedName = readNestedString(body, [
      "data",
      "attributes",
      "normalized_name",
    ]);
    const versionSpec = readNestedString(body, [
      "data",
      "attributes",
      "version_spec",
    ]);
    if (
      !normalizedName ||
      !versionSpec ||
      !hasCatalogArtifact(normalizedName)
    ) {
      sendJson(response, 404, {
        errors: [{ code: "registry_artifact_not_found" }],
      });
      return;
    }
    state.artifactEvents.push("submission");
    state.artifactSubmissionCount += 1;
    state.artifactTaskNormalizedName = normalizedName;
    state.artifactTaskReadCount = 0;
    state.artifactTaskVersionSpec = versionSpec;
    sendJson(
      response,
      202,
      { data: { id: artifactTaskId, type: "tasks" } },
      { "Content-Location": `/api/v1/tasks/${artifactTaskId}` },
    );
    return;
  }

  if (method === "GET" && pathname === `/api/v1/tasks/${artifactTaskId}`) {
    if (!state.artifactTaskNormalizedName || !state.artifactTaskVersionSpec) {
      sendJson(response, 404, { errors: [{ code: "fixture_task_not_found" }] });
      return;
    }

    state.artifactEvents.push("task-poll");
    state.artifactTaskReadCount += 1;
    const complete =
      state.artifactTaskReadCount >= 2 && !state.holdArtifactTask;
    if (complete) {
      state.tenantArtifacts.set(
        state.artifactTaskNormalizedName,
        state.artifactTaskVersionSpec,
      );
    }
    sendJson(response, 200, {
      data: {
        attributes: complete
          ? { state: "completed", result: { installed: true, error: null } }
          : { state: "executing" },
        id: artifactTaskId,
        type: "tasks",
      },
    });
    return;
  }

  if (
    method === "DELETE" &&
    pathname.startsWith("/api/v1/registry/artifacts/")
  ) {
    const normalizedName = decodeURIComponent(
      pathname.slice("/api/v1/registry/artifacts/".length),
    );
    state.tenantArtifacts.delete(normalizedName);
    sendJson(response, 204);
    return;
  }

  if (method === "GET" && pathname === "/api/v1/registry/providers") {
    sendDiscoveryResponse(response);
    return;
  }

  if (method === "GET" && pathname === "/api/v1/registry/available-artifacts") {
    if (state.discoveryMode !== "ready") {
      sendDiscoveryResponse(response);
      return;
    }
    const page = Number(url.searchParams.get("page[number]") ?? "1");
    const data = catalogPages[page - 1];
    if (!data) {
      sendJson(response, 400, { errors: [{ code: "invalid_fixture_page" }] });
      return;
    }
    sendJson(response, 200, {
      data,
      meta: { pagination: { count: 4, page, pages: 2 } },
    });
    return;
  }

  sendJson(response, 404, { errors: [{ code: "fixture_route_not_found" }] });
}

function bodyOrEmpty(body: unknown) {
  return body ?? {};
}

function sendDiscoveryResponse(response: ServerResponse) {
  if (state.discoveryMode === "ready") {
    sendJson(response, 200, {
      data: [
        {
          id: "fixturecloud",
          type: "registry-providers",
          attributes: { name: "Fixture Cloud", logo_url: null },
        },
      ],
    });
    return;
  }

  const responseByMode = {
    error: [500, "fixture_unexpected_failure"],
    reconnect: [502, "registry_key_rejected"],
    unavailable: [503, "registry_unavailable"],
  } as const;
  const [status, code] = responseByMode[state.discoveryMode];
  sendJson(response, status, { errors: [{ code }] });
}

function credentialDocument() {
  const active = state.credentialState === "active";
  return {
    data: {
      attributes: {
        configured: active || state.credentialState === "pending",
        is_valid: active,
        scopes: active ? ["fixture:registry"] : [],
        validation_pending: state.credentialState === "pending",
        validation_status: active ? "valid" : "pending",
      },
      type: "registry-credentials",
    },
  };
}

function currentUserDocument() {
  return {
    data: {
      attributes: {
        company_name: "Fixture Registry Company",
        date_joined: "2026-01-01T00:00:00Z",
        email: "registry-fixture-user@example.test",
        name: "Fixture Registry Manager",
      },
      id: "fixture-registry-user",
      type: "users",
    },
    included: [
      {
        attributes: {
          manage_registry: state.hasCurrentAuthority,
          manage_providers: true,
          manage_scans: true,
          unlimited_visibility: true,
          manage_billing: false,
        },
        id: "fixture-registry-role",
        type: "roles",
      },
    ],
  };
}

function tenantArtifactsDocument() {
  return {
    data: Array.from(state.tenantArtifacts, ([id, versionSpec]) => ({
      attributes: {
        inserted_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
        version_spec: versionSpec,
      },
      id,
      type: "registry-artifacts",
    })),
  };
}

function tokenDocument() {
  return {
    data: {
      attributes: {
        access: fixtureAccessToken,
        refresh: "fixture-refresh-token-not-a-secret",
      },
      type: "tokens",
    },
  };
}

function catalogArtifact(id: string, attributes: Record<string, unknown>) {
  return { attributes, id, type: "registry-artifacts" };
}

function hasCatalogArtifact(normalizedName: string) {
  return catalogPages.flat().some((artifact) => artifact.id === normalizedName);
}

function base64UrlJson(value: Record<string, unknown>) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  if (chunks.length === 0) return undefined;
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
}

function readStringField(value: unknown, field: string) {
  return isRecord(value) && typeof value[field] === "string"
    ? value[field]
    : undefined;
}

function readNestedString(value: unknown, path: string[]) {
  let current = value;
  for (const segment of path) {
    if (!isRecord(current)) return undefined;
    current = current[segment];
  }
  return typeof current === "string" ? current : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function sendJson(
  response: ServerResponse,
  status: number,
  payload?: unknown,
  headers: Record<string, string> = {},
) {
  response.writeHead(status, {
    "Cache-Control": "no-store",
    ...(payload === undefined
      ? {}
      : { "Content-Type": "application/vnd.api+json" }),
    ...headers,
  });
  response.end(payload === undefined ? undefined : JSON.stringify(payload));
}

function collectionDocument(data: unknown[]) {
  return {
    data,
    meta: { pagination: { page: 1, pages: 1, count: data.length } },
  };
}
function providerResource() {
  return {
    id: fixtureProviderId,
    type: "providers",
    attributes: {
      provider: "fixturecloud",
      uid: state.providerUid,
      alias: state.providerAlias,
      is_dynamic: true,
      status: "completed",
      available: true,
      resources: state.scanCreated ? 1 : 0,
      connection: {
        connected: state.connected,
        last_checked_at: state.connected ? "2026-01-01T00:00:00Z" : null,
      },
      scanner_args: {},
      inserted_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    },
    relationships: {
      secret: {
        data: state.secretSaved
          ? { id: fixtureSecretId, type: "provider-secrets" }
          : null,
      },
      provider_groups: { data: [], meta: { count: 0 } },
    },
  };
}
function scanResource() {
  return {
    id: fixtureScanId,
    type: "scans",
    attributes: {
      name: "Fixture Registry scan",
      state: "completed",
      trigger: "manual",
      progress: 100,
      unique_resource_count: 1,
      duration: 1,
      scanner_args: {},
      started_at: "2026-01-01T00:00:00Z",
      inserted_at: "2026-01-01T00:00:00Z",
      completed_at: "2026-01-01T00:00:01Z",
      scheduled_at: null,
      next_scan_at: null,
    },
    relationships: {
      provider: { data: { id: fixtureProviderId, type: "providers" } },
      task: { data: null },
    },
  };
}
