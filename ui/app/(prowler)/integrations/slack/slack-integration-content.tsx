import { getIntegrations } from "@/actions/integrations/integrations";
import { getSlackAuthorizeUrl } from "@/actions/integrations/slack";
import { SlackIntegrationManager } from "@/components/integrations/slack/slack-integration-manager";
import { GENERIC_SERVER_ERROR_MESSAGE } from "@/lib/helper";
import { INTEGRATION_TYPE, type IntegrationProps } from "@/types/integrations";

/**
 * `getIntegrations` throws a `>= 500` answer past its own catch, which covers
 * only transport. Uncaught it trips the route's error boundary and replaces a
 * page that could still offer the install, so report it as `{ error }` and take
 * the page's one error path.
 */
const readSlackIntegrations = async (searchParams: URLSearchParams) => {
  try {
    return await getIntegrations(searchParams);
  } catch {
    // The thrown message can carry the server's own wording; `handleApiResponse`
    // already reported it to Sentry.
    return { error: GENERIC_SERVER_ERROR_MESSAGE };
  }
};

/**
 * Split out of `page.tsx` so the browser-mode tests can render it without the
 * surrounding `ContentLayout`.
 */
export async function SlackIntegrationContent() {
  const searchParams = new URLSearchParams();
  searchParams.set("filter[integration_type]", INTEGRATION_TYPE.SLACK);
  // One workspace per tenant, so one row is the whole result set.
  searchParams.set("page[size]", "1");

  const integrations = await readSlackIntegrations(searchParams);
  const loadError =
    integrations && "error" in integrations
      ? (integrations.error as string)
      : null;
  const integration: IntegrationProps | null =
    (integrations?.data?.[0] as IntegrationProps | undefined) ?? null;

  const authorize = integration ? null : await getSlackAuthorizeUrl();

  return (
    <SlackIntegrationManager
      integration={integration}
      authorizeUrl={
        authorize && "authorizeUrl" in authorize ? authorize.authorizeUrl : null
      }
      unavailable={Boolean(authorize && "unavailable" in authorize)}
      // Rate limited is not unavailable: the install is still on offer, it just
      // cannot be started yet.
      rateLimitMessage={
        authorize && "rateLimited" in authorize ? authorize.message : null
      }
      loadError={
        loadError ??
        (authorize && "error" in authorize ? authorize.error : null)
      }
    />
  );
}
