import { http, HttpResponse } from "msw";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "https://api.test.prowler.com/api/v1";

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
];
