const fixtureBaseUrl = "http://127.0.0.1:4300";

export const FIXTURE_REGISTRY_KEY = "fixture-registry-key-not-a-secret";

export const controlledRegistryFixture = {
  async reset() {
    await request("/__fixture__/registry/reset", { method: "POST" });
  },
  async revokeCurrentAuthority() {
    await request("/__fixture__/registry/revoke-current-authority", {
      method: "POST",
    });
  },
  async setDiscoveryMode(mode: "error" | "reconnect" | "unavailable") {
    await request("/__fixture__/registry/discovery-mode", {
      body: JSON.stringify({ mode }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
    });
  },
  async snapshot() {
    return request<FixtureSnapshot>("/__fixture__/registry/snapshot");
  },
};

interface FixtureSnapshot {
  credentialAccepted: boolean;
  credentialReadCount: number;
  taskReadCount: number;
}

async function request<TResponse = undefined>(
  path: string,
  init?: RequestInit,
): Promise<TResponse> {
  const response = await fetch(`${fixtureBaseUrl}${path}`, init);
  if (!response.ok) {
    throw new Error(
      `Controlled Registry fixture request failed: ${response.status}`,
    );
  }
  return (await response.json()) as TResponse;
}
