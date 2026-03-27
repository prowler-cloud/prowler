import { http, HttpResponse } from "msw";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "https://some-api-server/api/v1";
1;
/**
 * Default MSW handlers for the prowler backend API.
 * These provide sensible defaults for server action tests.
 * Override per-test with `server.use(...)` for specific scenarios.
 */
export const handlers = [
  // Tenant switch
  http.post(`${API_BASE}/tokens/switch`, () => {
    return HttpResponse.json({
      data: {
        attributes: {
          access: "test-access-token",
          refresh: "test-refresh-token",
        },
      },
    });
  }),

  // Create tenant
  http.post(`${API_BASE}/tenants`, async ({ request }) => {
    const body = (await request.json()) as any;
    return HttpResponse.json({
      data: {
        id: "new-tenant-id",
        type: "tenants",
        attributes: { name: body?.data?.attributes?.name ?? "New Org" },
      },
    });
  }),

  // Update tenant name
  http.patch(`${API_BASE}/tenants/:tenantId`, () => {
    return HttpResponse.json({
      data: { type: "tenants", attributes: { name: "Updated" } },
    });
  }),

  // Delete tenant
  http.delete(`${API_BASE}/tenants/:tenantId`, () => {
    return new HttpResponse(null, { status: 204 });
  }),
];
