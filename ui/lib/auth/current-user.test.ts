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

  it("combines exact-true permissions from every assigned role", async () => {
    // Given
    fetchMock.mockResolvedValue(
      reply(
        document([
          {
            ...role(false),
            attributes: {
              manage_providers: true,
              manage_scans: false,
              manage_registry: false,
              manage_users: "true",
            },
          },
          {
            ...role(true),
            id: "role-2",
            attributes: {
              manage_providers: false,
              manage_scans: true,
              manage_registry: true,
              manage_users: 1,
            },
          },
        ]),
      ),
    );

    // When
    const result = await fetchCurrentUser("access-token");

    // Then
    expect(result.permissions).toMatchObject({
      manage_providers: true,
      manage_scans: true,
      manage_registry: true,
      manage_users: false,
      manage_account: false,
    });
    expect(result.manageRegistry).toBe(true);
  });

  it.each([
    { assignments: [true, false], expected: true },
    { assignments: [true, undefined], expected: true },
    { assignments: [false, false], expected: false },
    { assignments: [false, undefined], expected: undefined },
    { assignments: [false, "true"], expected: undefined },
  ])(
    "resolves Registry authority across $assignments",
    async ({ assignments, expected }) => {
      // Given
      fetchMock.mockResolvedValue(
        reply(
          document(
            assignments.map((permission, index) => ({
              ...role(permission),
              id: `role-${index}`,
            })),
          ),
        ),
      );

      // When / Then
      await expect(fetchCurrentUser("access-token")).resolves.toMatchObject({
        manageRegistry: expected,
        permissions: { manage_registry: expected === true },
      });
    },
  );

  it.each([
    [document([]), 200],
    [{ data: { type: "users" } }, 200],
    [document([role(true)]), 401],
    [document([role(true)]), 403],
    [document([role(true)]), 500],
  ])(
    "rejects absent, malformed, or unsuccessful evidence",
    async (body, status) => {
      // Given
      fetchMock.mockResolvedValue(reply(body, status));
      // When / Then
      await expect(fetchCurrentUser("access-token")).rejects.toThrow();
    },
  );
});
