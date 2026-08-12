import { getIntegrations } from "@/actions/integrations/integrations";
import { getSlackAuthorizeUrl } from "@/actions/integrations/slack";
import { SlackIntegrationManager } from "@/components/integrations/slack/slack-integration-manager";
import type { IntegrationProps } from "@/types/integrations";

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

  const integrations = await getIntegrations(searchParams);
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
      loadError={
        loadError ??
        (authorize && "error" in authorize ? authorize.error : null)
      }
    />
  );
}
