import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock } = vi.hoisted(() => ({ fetchMock: vi.fn() }));
vi.mock("@/lib", () => ({ apiBaseUrl: "https://api.example.com/api/v1" }));

import { fetchCurrentUser } from "./current-user";

const role = (manage_registry: unknown) => ({
  type: "roles",
  id: "role-1",
  attributes: { manage_registry },
});
const document = (roles: unknown) => ({
  data: {
    type: "users",
    id: "user-1",
    attributes: { name: "Jane", email: "jane@example.com" },
  },
  included: roles,
});
const reply = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status });

describe("fetchCurrentUser", () => {
  beforeEach(() => vi.stubGlobal("fetch", fetchMock));

  it("accepts one current exact-true role without caching", async () => {
    // Given
    fetchMock.mockResolvedValue(reply(document([role(true)])));
    const controller = new AbortController();
    // When
    const result = await fetchCurrentUser("access-token", {
      signal: controller.signal,
    });
    // Then
    expect(result.manageRegistry).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/api/v1/users/me?include=roles",
      expect.objectContaining({ cache: "no-store", signal: controller.signal }),
    );
  });

  it.each([
    [false, false],
    [undefined, undefined],
    ["true", undefined],
  ])(
    "keeps only exact boolean authority for %j",
    async (permission, expected) => {
      // Given
      fetchMock.mockResolvedValue(reply(document([role(permission)])));
      // When / Then
      await expect(fetchCurrentUser("access-token")).resolves.toMatchObject({
        manageRegistry: expected,
        permissions: { manage_registry: permission === true },
      });
    },
  );

  it.each([
    [document([]), 200],
    [document([role(true), role(true)]), 200],
    [{ data: { type: "users" } }, 200],
    [document([role(true)]), 401],
    [document([role(true)]), 403],
    [document([role(true)]), 500],
  ])(
    "rejects absent, ambiguous, malformed, or unsuccessful evidence",
    async (body, status) => {
      // Given
      fetchMock.mockResolvedValue(reply(body, status));
      // When / Then
      await expect(fetchCurrentUser("access-token")).rejects.toThrow();
    },
  );
});
