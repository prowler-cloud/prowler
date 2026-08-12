import { ApiKeyLinkCard } from "@/components/integrations/api-key/api-key-link-card";
import { JiraIntegrationCard } from "@/components/integrations/jira/jira-integration-card";
import { S3IntegrationCard } from "@/components/integrations/s3/s3-integration-card";
import { SecurityHubIntegrationCard } from "@/components/integrations/security-hub/security-hub-integration-card";
import { SlackIntegrationCard } from "@/components/integrations/slack/slack-integration-card";
import { SsoLinkCard } from "@/components/integrations/sso/sso-link-card";
import { isCloud } from "@/lib/shared/env";

/**
 * The integrations catalogue, split out of `page.tsx` so it can be rendered
 * without the surrounding `ContentLayout` (whose navbar streams async server
 * children a client renderer can't resolve) in the browser-mode tests.
 */
export function IntegrationsContent() {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-4">
        <p className="text-sm text-gray-600 dark:text-gray-300">
          Connect external services to enhance your security workflow and
          automatically export your scan results.
        </p>
      </div>

      <div className="grid gap-6">
        {/* Amazon S3 Integration */}
        <S3IntegrationCard />

        {/* AWS Security Hub Integration */}
        <SecurityHubIntegrationCard />

        {/* Jira Integration */}
        <JiraIntegrationCard />

        {/* Slack Integration — its API lives in the cloud deployment only, so
            a self-hosted Prowler has nothing to manage. */}
        {isCloud() && <SlackIntegrationCard />}

        {/* SSO Configuration - redirects to Profile */}
        <SsoLinkCard />

        {/* API Keys - redirects to Profile */}
        <ApiKeyLinkCard />
      </div>
    </div>
  );
}
