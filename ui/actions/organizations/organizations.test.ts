import { beforeEach, describe, expect, it, vi } from "vitest";

import { ORG_SECRET_TYPE, ORGANIZATION_TYPE } from "@/types/organizations";

const {
  fetchMock,
  getAuthHeadersMock,
  handleApiErrorMock,
  handleApiResponseMock,
  revalidatePathMock,
} = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
  handleApiErrorMock: vi.fn(),
  handleApiResponseMock: vi.fn(),
  revalidatePathMock: vi.fn(),
}));

vi.mock("next/cache", () => ({
  revalidatePath: revalidatePathMock,
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiError: handleApiErrorMock,
  handleApiResponse: handleApiResponseMock,
}));

import {
  applyDiscovery,
  createOrganization,
  getDiscovery,
  listOrganizationNodesSafe,
  listOrganizationsSafe,
  triggerDiscovery,
  updateOrganizationSecret,
} from "./organizations";

describe("organizations actions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiErrorMock.mockReturnValue({ error: "Unexpected error" });
  });

  it("rejects invalid organization secret identifiers", async () => {
    // When
    const result = await updateOrganizationSecret("../secret-id", {
      orgType: ORGANIZATION_TYPE.AWS,
      secretType: ORG_SECRET_TYPE.ROLE,
      secret: {
        role_arn: "arn:aws:iam::123456789012:role/ProwlerOrgRole",
        external_id: "o-abc123def4",
      },
    });

    // Then
    expect(result).toEqual({ error: "Invalid organization secret ID" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects invalid discovery identifiers before building the request URL", async () => {
    // When
    const result = await getDiscovery(
      "123e4567-e89b-12d3-a456-426614174000",
      "discovery/../id",
    );

    // Then
    expect(result).toEqual({ error: "Invalid discovery ID" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects invalid organization identifiers before triggering discovery", async () => {
    // When
    const result = await triggerDiscovery("org/id-with-slash");

    // Then
    expect(result).toEqual({ error: "Invalid organization ID" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects an organization type with no onboarding flow instead of coercing it", async () => {
    // Given a form asking for a type this build cannot onboard. `oraclecloud` is
    // a real provider the API can report an organization for — display supports
    // it, onboarding does not — so it is the exact boundary a blind cast would
    // let through.
    const formData = new FormData();
    formData.set("name", "Tenancy");
    formData.set("externalId", "ocid1.tenancy.oc1..aaaa1111");
    formData.set("orgType", "oraclecloud");

    // When
    const result = await createOrganization(formData);

    // Then it never reaches the API: silently creating an AWS organization
    // would onboard something the caller never asked for.
    expect(result).toEqual({ error: "Invalid organization type" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects an unrecognized organization type value", async () => {
    // Given a garbage value, and an empty one: present-but-empty is a different
    // case from absent, and only absent may fall back to AWS.
    for (const orgType of ["not-a-provider", ""]) {
      const formData = new FormData();
      formData.set("name", "Rogue");
      formData.set("externalId", "o-abc123def4");
      formData.set("orgType", orgType);

      // When
      const result = await createOrganization(formData);

      // Then
      expect(result).toEqual({ error: "Invalid organization type" });
    }

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("defaults to AWS only when the organization type is absent", async () => {
    // Given a form from before the field existed.
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: { id: "org-1" } }), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );
    handleApiResponseMock.mockResolvedValue({ data: { id: "org-1" } });

    const formData = new FormData();
    formData.set("name", "Legacy");
    formData.set("externalId", "o-abc123def4");

    // When
    await createOrganization(formData);

    // Then the absent value — and only the absent value — means AWS.
    const body = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body));
    expect(body.data.attributes.org_type).toBe(ORGANIZATION_TYPE.AWS);
  });

  it("revalidates providers only when apply discovery succeeds", async () => {
    // Given
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: { id: "apply-1" } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    handleApiResponseMock.mockResolvedValueOnce({ error: "Apply failed" });
    handleApiResponseMock.mockResolvedValueOnce({ data: { id: "apply-1" } });

    // When
    const failedResult = await applyDiscovery(
      "123e4567-e89b-12d3-a456-426614174000",
      "223e4567-e89b-12d3-a456-426614174111",
      { orgType: ORGANIZATION_TYPE.AWS, accounts: [], organizationalUnits: [] },
    );
    const successfulResult = await applyDiscovery(
      "123e4567-e89b-12d3-a456-426614174000",
      "223e4567-e89b-12d3-a456-426614174111",
      { orgType: ORGANIZATION_TYPE.AWS, accounts: [], organizationalUnits: [] },
    );

    // Then
    expect(failedResult).toEqual({ error: "Apply failed" });
    expect(successfulResult).toEqual({ data: { id: "apply-1" } });
    expect(revalidatePathMock).toHaveBeenCalledTimes(1);
    expect(revalidatePathMock).toHaveBeenCalledWith("/providers");
  });

  it("revalidates providers when response contains error set to null", async () => {
    // Given
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: { id: "apply-2" } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    handleApiResponseMock.mockResolvedValueOnce({
      data: { id: "apply-2" },
      error: null,
    });

    // When
    const result = await applyDiscovery(
      "123e4567-e89b-12d3-a456-426614174000",
      "223e4567-e89b-12d3-a456-426614174111",
      { orgType: ORGANIZATION_TYPE.AWS, accounts: [], organizationalUnits: [] },
    );

    // Then
    expect(result).toEqual({ data: { id: "apply-2" }, error: null });
    expect(revalidatePathMock).toHaveBeenCalledTimes(1);
    expect(revalidatePathMock).toHaveBeenCalledWith("/providers");
  });

  it("lists organizations across all types without a hardcoded org_type filter", async () => {
    // Given
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    handleApiResponseMock.mockResolvedValue({ data: [] });

    // When
    const result = await listOrganizationsSafe();

    // Then
    expect(result).toEqual({ data: [] });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      "https://api.example.com/api/v1/organizations?page%5Bnumber%5D=1&page%5Bsize%5D=100",
    );
  });

  it("lists organization nodes from the canonical endpoint", async () => {
    // Given
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    handleApiResponseMock.mockResolvedValue({ data: [] });

    // When
    const result = await listOrganizationNodesSafe();

    // Then
    expect(result).toEqual({ data: [] });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      "https://api.example.com/api/v1/organization-nodes?page%5Bnumber%5D=1&page%5Bsize%5D=100",
    );
  });

  it("follows JSON:API pagination so hierarchy groups are never truncated", async () => {
    // Given a collection spanning three pages.
    const okResponse = () =>
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    fetchMock.mockResolvedValue(okResponse());
    handleApiResponseMock
      .mockResolvedValueOnce({
        data: [{ id: "node-1" }],
        meta: { pagination: { page: 1, pages: 3, count: 3 } },
      })
      .mockResolvedValueOnce({
        data: [{ id: "node-2" }],
        meta: { pagination: { page: 2, pages: 3, count: 3 } },
      })
      .mockResolvedValueOnce({
        data: [{ id: "node-3" }],
        meta: { pagination: { page: 3, pages: 3, count: 3 } },
      });

    // When
    const result = await listOrganizationNodesSafe();

    // Then every page is requested once and the pages are merged in order.
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(
      fetchMock.mock.calls.map((call) =>
        new URL(call[0] as string).searchParams.get("page[number]"),
      ),
    ).toEqual(["1", "2", "3"]);
    expect(result).toEqual({
      data: [{ id: "node-1" }, { id: "node-2" }, { id: "node-3" }],
    });
  });

  it("degrades instead of returning a partial hierarchy when a later page fails", async () => {
    // Given a first page announcing more pages, then a failure.
    fetchMock
      .mockResolvedValueOnce(
        new Response(JSON.stringify({}), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      )
      .mockResolvedValueOnce(
        new Response("Internal Server Error", { status: 500 }),
      );
    handleApiResponseMock.mockResolvedValueOnce({
      data: [{ id: "node-1" }],
      meta: { pagination: { page: 1, pages: 2, count: 2 } },
    });

    // When
    const result = await listOrganizationNodesSafe();

    // Then the half-fetched hierarchy is dropped: the page shows its degraded
    // notice with a flat provider list instead of partial grouping.
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result).toEqual({ data: [], error: true });
  });

  it("flags an empty organizations payload as degraded when the safe request fails", async () => {
    // Given a 5xx. The mock THROWS because that is what the real helper does
    // (server-actions-helper captures to Sentry, then rethrows) — resolving
    // instead would test a path production never takes.
    fetchMock.mockResolvedValue(
      new Response("Internal Server Error", {
        status: 500,
      }),
    );
    handleApiResponseMock.mockRejectedValue(new Error("Server error (500)"));

    // When
    const result = await listOrganizationsSafe();

    // Then the caller still gets the degraded result, and the failure passed
    // through the shared reporting point on its way there — so a 5xx behind the
    // degraded-hierarchy notice is traceable instead of only a boolean.
    expect(result).toEqual({ data: [], error: true });
    expect(handleApiResponseMock).toHaveBeenCalledTimes(1);
    expect(handleApiErrorMock).toHaveBeenCalledTimes(1);
  });

  it("flags an empty organization nodes payload as degraded when the safe request fails", async () => {
    // Given
    fetchMock.mockResolvedValue(
      new Response("Internal Server Error", {
        status: 500,
      }),
    );
    handleApiResponseMock.mockRejectedValue(new Error("Server error (500)"));

    // When
    const result = await listOrganizationNodesSafe();

    // Then — same contract as the organizations read above.
    expect(result).toEqual({ data: [], error: true });
    expect(handleApiResponseMock).toHaveBeenCalledTimes(1);
    expect(handleApiErrorMock).toHaveBeenCalledTimes(1);
  });

  it("reports a rejected request instead of degrading silently", async () => {
    // A transport failure never reaches `handleApiResponse`, so the catch is the
    // only place it can be reported.
    fetchMock.mockRejectedValue(new TypeError("fetch failed"));

    // When
    const result = await listOrganizationNodesSafe();

    // Then
    expect(result).toEqual({ data: [], error: true });
    expect(handleApiResponseMock).not.toHaveBeenCalled();
    expect(handleApiErrorMock).toHaveBeenCalledTimes(1);
  });

  it("degrades instead of escaping when the session lookup throws", async () => {
    // An escape here would take down the providers page's whole `Promise.all`.
    getAuthHeadersMock.mockRejectedValue(new Error("No session"));

    // When
    const result = await listOrganizationsSafe();

    // Then
    expect(result).toEqual({ data: [], error: true });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reports guard exhaustion instead of degrading silently past 50 pages", async () => {
    // Given a collection that always announces more pages than fetched, so the
    // runaway guard fires (50 × 100 = 5,000 resources). An estate that large
    // degrading with only a boolean would be indistinguishable from ordinary
    // fetch failures in Sentry.
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    handleApiResponseMock.mockResolvedValue({
      data: [{ id: "node-1" }],
      meta: { pagination: { page: 1, pages: 51, count: 5100 } },
    });

    // When
    const result = await listOrganizationNodesSafe();

    // Then the hierarchy degrades, and the guard firing is reported as a
    // concrete error through the shared reporting point on its way there.
    expect(fetchMock).toHaveBeenCalledTimes(50);
    expect(result).toEqual({ data: [], error: true });
    expect(handleApiErrorMock).toHaveBeenCalledTimes(1);
    expect(handleApiErrorMock).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.stringContaining("pagination guard"),
      }),
    );
  });

  it("reports a 4xx page through the shared helper before degrading", async () => {
    // Given a 403. The real helper reports it and RETURNS (only 5xx throws), so
    // the degraded result must not depend on an exception — and the report must
    // still happen, which the pre-fix early return skipped.
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ errors: [{ detail: "Forbidden" }] }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }),
    );
    handleApiResponseMock.mockResolvedValue({
      error: "Forbidden",
      status: 403,
    });

    // When
    const result = await listOrganizationNodesSafe();

    // Then
    expect(result).toEqual({ data: [], error: true });
    expect(handleApiResponseMock).toHaveBeenCalledTimes(1);
  });
});
