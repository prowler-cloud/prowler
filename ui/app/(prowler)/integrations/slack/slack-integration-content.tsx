import { getIntegrations } from "@/actions/integrations/integrations";
import { getSlackAuthorizeUrl } from "@/actions/integrations/slack";
import { SlackIntegrationManager } from "@/components/integrations/slack/slack-integration-manager";
import { GENERIC_SERVER_ERROR_MESSAGE } from "@/lib/helper";
import type { IntegrationProps } from "@/types/integrations";

/**
 * Read the tenant's Slack row, reporting a server failure the same way the API's
 * own refusals arrive — as `{ error }` — so both take the page's one error path.
 *
 * `getIntegrations` returns its `handleApiResponse(...)` promise without
 * awaiting it, so its own `catch` covers only a transport failure: a `>= 500`
 * answer is *thrown*, past that catch, at whoever awaited the action. Left
 * uncaught it escapes this page and trips the route's error boundary, replacing
 * a page that could still offer the install with a full-page error. Awaiting
 * inside the shared action would fix this rejection in the wrong place: the
 * Jira / S3 / Security Hub pages read the same result with nowhere to route an
 * error into, so they would silently render an empty list instead.
 *
 * `handleApiResponse` already reported the throw to Sentry, so this only
 * classifies it.
 */
const readSlackIntegrations = async (searchParams: URLSearchParams) => {
  try {
    return await getIntegrations(searchParams);
  } catch {
    // The thrown message can carry the server's own wording; a server error is
    // answered in Prowler's, as the rest of the UI answers one.
    return { error: GENERIC_SERVER_ERROR_MESSAGE };
  }
};

/**
 * Loads the tenant's Slack install and, when there is none, the consent URL to
 * start one — split out of `page.tsx` so it can be rendered without the
 * surrounding `ContentLayout` in the browser-mode tests.
 *
 * The authorize URL is requested here rather than behind the Connect click:
 * minting a short-lived, single-use OAuth state costs nothing, it keeps the
 * install one click (a plain link to Slack's consent screen, no interstitial),
 * and it is what surfaces "Slack isn't available in this environment yet" on
 * arrival instead of after a click that goes nowhere. It is skipped entirely
 * once a workspace is connected — there is no install left to start.
 */
export async function SlackIntegrationContent() {
  // The React Compiler (enabled for the browser-mode project) otherwise
  // instruments this as a client component and injects `useMemoCache`, which
  // needs a React dispatcher. An async server component renders once per
  // request, so there is nothing to memoize — and the injected hook makes it
  // uncallable outside a render, which is exactly how the tests mount it.
  "use no memo";

  const searchParams = new URLSearchParams();
  searchParams.set("filter[integration_type]", "slack");
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
      // Slack being busy is not the same as this deployment having no Slack
      // app: the install is still on offer, it just cannot be started yet.
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
