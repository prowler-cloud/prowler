import { beforeEach, describe, expect, it, vi } from "vitest";

const { authMock, fetchMock } = vi.hoisted(() => ({
  authMock: vi.fn(),
  fetchMock: vi.fn(),
}));

vi.mock("@/auth.config", () => ({ auth: authMock }));
vi.mock("@/lib", () => ({ apiBaseUrl: "https://api.test/api/v1" }));

import { getProviderSchemas } from "./provider-schemas";

const schemaResponse = (providerType = "acme") =>
  new Response(
    JSON.stringify({
      data: {
        type: "provider-schemas",
        id: providerType,
        attributes: { secret_types: {} },
      },
    }),
    { status: 200 },
  );

describe("getProviderSchemas", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    authMock.mockResolvedValue({ accessToken: "access-token" });
    fetchMock.mockResolvedValue(schemaResponse());
  });

  it("requests the normalized provider schema with authenticated JSON:API headers", async () => {
    // When
    const result = await getProviderSchemas(" ACME ");

    // Then
    expect(result).toEqual({
      status: "success",
      providerType: "acme",
      secretTypes: {},
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/api/v1/provider-schemas/acme",
      {
        cache: "no-store",
        headers: {
          Accept: "application/vnd.api+json",
          Authorization: "Bearer access-token",
        },
      },
    );
  });

  it("does not fetch invalid input and encodes a normalized path segment", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(schemaResponse("acme/team"));

    // When
    const invalid = await Promise.all([
      getProviderSchemas(" "),
      getProviderSchemas("a".repeat(51)),
    ]);
    const encoded = await getProviderSchemas(" ACME/TEAM ");

    // Then
    expect(invalid).toEqual([{ status: "error" }, { status: "error" }]);
    expect(encoded).toMatchObject({
      status: "success",
      providerType: "acme/team",
    });
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/api/v1/provider-schemas/acme%2Fteam",
      expect.any(Object),
    );
  });

  it("denies an unauthenticated request without fetching", async () => {
    // Given
    authMock.mockResolvedValue({});

    // When
    const result = await getProviderSchemas("acme");

    // Then
    expect(result).toEqual({ status: "access_denied" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    [401, { status: "access_denied" }],
    [403, { status: "access_denied" }],
    [404, { status: "not_found" }],
    [409, { status: "unavailable" }],
    [500, { status: "error" }],
  ])("maps HTTP %i to a safe result", async (status, expected) => {
    // Given
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ errors: [{ detail: "private detail" }] }), {
        status,
      }),
    );

    // When
    const result = await getProviderSchemas("acme");

    // Then
    expect(result).toEqual(expected);
    expect(JSON.stringify(result)).not.toContain("private detail");
  });

  it("returns a generic safe error when fetch rejects", async () => {
    // Given
    const rejection = new Error("connection detail must not leak");
    fetchMock.mockRejectedValueOnce(rejection);

    // When
    const result = await getProviderSchemas("acme");

    // Then
    expect(result).toEqual({ status: "error" });
    expect(JSON.stringify(result)).not.toContain(rejection.message);
  });

  it("distinguishes a malformed success document from a transport failure", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ errors: [] })),
    );

    // When
    const result = await getProviderSchemas("acme");

    // Then
    expect(result).toEqual({ status: "malformed" });
  });
});
