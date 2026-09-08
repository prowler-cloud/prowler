import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, getProviderSchemas, getAuthHeaders, revalidatePath } =
  vi.hoisted(() => ({
    fetchMock: vi.fn(),
    getProviderSchemas: vi.fn(),
    getAuthHeaders: vi.fn(),
    revalidatePath: vi.fn(),
  }));
vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.test/api/v1",
  getAuthHeaders,
}));
vi.mock("next/cache", () => ({ revalidatePath }));
vi.mock("./provider-schemas", () => ({ getProviderSchemas }));

import { saveDynamicProviderCredentials } from "./dynamic-provider-credentials";

const input = {
  providerId: "account",
  secretType: "api_key",
  secret: { token: "private-value" },
};
const response = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status });
const account = (secretId: string | null = null) => ({
  data: {
    id: "account",
    attributes: { provider: "acme" },
    relationships: { secret: { data: secretId ? { id: secretId } : null } },
  },
});

describe("dynamic provider credential actions", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
    getAuthHeaders.mockResolvedValue({ Authorization: "Bearer test" });
    getProviderSchemas.mockResolvedValue({
      status: "success",
      providerType: "acme",
      secretTypes: {
        api_key: {
          type: "object",
          properties: {
            token: { type: "string", format: "password", writeOnly: true },
          },
          required: ["token"],
        },
      },
    });
  });
  it("validates the account's current schema and sends JSON credentials without the builtin mapping", async () => {
    fetchMock
      .mockResolvedValueOnce(response(account()))
      .mockResolvedValueOnce(response({ data: { id: "saved" } }, 201));
    expect(await saveDynamicProviderCredentials(input)).toEqual({
      status: "saved",
      secretId: "saved",
    });
    expect(getProviderSchemas).toHaveBeenCalledWith("acme");
    const [url, request] = fetchMock.mock.calls[1];
    expect(url).toBe("https://api.test/api/v1/providers/secrets");
    expect(JSON.parse(request.body).data).toEqual({
      type: "provider-secrets",
      attributes: {
        secret_type: "api_key",
        secret: { token: "private-value" },
      },
      relationships: {
        provider: { data: { id: "account", type: "providers" } },
      },
    });
  });
  it("updates the authoritative existing secret, including after a retry", async () => {
    fetchMock
      .mockResolvedValueOnce(response(account("existing")))
      .mockResolvedValueOnce(response({ data: { id: "existing" } }));
    expect((await saveDynamicProviderCredentials(input)).status).toBe("saved");
    expect(
      fetchMock.mock.calls[1][0].endsWith("/providers/secrets/existing"),
    ).toBe(true);
    expect(fetchMock.mock.calls[1][1].method).toBe("PATCH");
  });
  it.each([
    { ...input, secretType: "invented" },
    { ...input, secret: { token: "" } },
    { ...input, secret: { token: "x", unknown: "hidden" } },
  ])("does not write invalid credentials", async (values) => {
    fetchMock.mockResolvedValueOnce(response(account()));
    expect((await saveDynamicProviderCredentials(values)).status).not.toBe(
      "saved",
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
  it("fails closed for an absent schema, revoked permission, and malformed accounts", async () => {
    getProviderSchemas.mockResolvedValue({
      status: "success",
      providerType: "acme",
      secretTypes: {},
    });
    fetchMock.mockResolvedValueOnce(response(account()));
    expect((await saveDynamicProviderCredentials(input)).status).toBe(
      "schema_unavailable",
    );
    fetchMock.mockResolvedValueOnce(response({}, 403));
    expect((await saveDynamicProviderCredentials(input)).status).toBe(
      "access_denied",
    );
    fetchMock.mockResolvedValueOnce(response({}));
    expect((await saveDynamicProviderCredentials(input)).status).toBe("error");
    expect(fetchMock.mock.calls.every(([, options]) => !options.method)).toBe(
      true,
    );
  });
  it("does not echo a rejected secret in errors", async () => {
    fetchMock
      .mockResolvedValueOnce(response(account()))
      .mockResolvedValueOnce(
        response({ errors: [{ detail: "private-value invalid" }] }, 400),
      );
    expect(
      JSON.stringify(await saveDynamicProviderCredentials(input)),
    ).not.toContain("private-value");
  });
});
