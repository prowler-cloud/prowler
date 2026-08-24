import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";

const port = 4300;
const taskId = "fixture-registry-validation-task";
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

interface FixtureState {
  credentialAccepted: boolean;
  credentialReadCount: number;
  credentialState: CredentialState;
  discoveryMode: DiscoveryMode;
  hasCurrentAuthority: boolean;
  taskReadCount: number;
  tenantArtifacts: Map<string, string>;
}

const initialState = (): FixtureState => ({
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
      is_official: true,
      is_verified: true,
      latest_version: "1.2.3",
      name: "Fixture network audit",
      providers: ["aws"],
    }),
    catalogArtifact("fixture-shared-policy", {
      description: "Synthetic Registry fixture shared policy",
      has_compliance: true,
      latest_version: "2.0.0",
      name: "Fixture shared policy",
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
      credentialAccepted: state.credentialAccepted,
      credentialReadCount: state.credentialReadCount,
      taskReadCount: state.taskReadCount,
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
        attributes: { state: complete ? "completed" : "executing" },
        id: taskId,
        type: "tasks",
      },
    });
    return;
  }

  if (method === "GET" && pathname === "/api/v1/registry/my-artifacts") {
    sendJson(response, 200, tenantArtifactsDocument());
    return;
  }

  if (method === "POST" && pathname === "/api/v1/registry/my-artifacts") {
    const body = bodyOrEmpty(await readJson(request));
    const normalizedName = readNestedString(body, ["data", "id"]);
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
    state.tenantArtifacts.set(normalizedName, versionSpec);
    sendJson(response, 201, {
      data: { id: normalizedName, type: "registry-tenant-artifacts" },
    });
    return;
  }

  if (
    method === "DELETE" &&
    pathname.startsWith("/api/v1/registry/my-artifacts/")
  ) {
    const normalizedName = decodeURIComponent(
      pathname.slice("/api/v1/registry/my-artifacts/".length),
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
      meta: { pagination: { count: 3, page, pages: 2 } },
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
    sendJson(response, 200, { data: [] });
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
        attributes: { manage_registry: state.hasCurrentAuthority },
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
      type: "registry-tenant-artifacts",
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
