import {
  ApiKeyLinkCard,
  JiraIntegrationCard,
  S3IntegrationCard,
  SecurityHubIntegrationCard,
  SsoLinkCard,
} from "@/components/integrations";
import { ContentLayout } from "@/components/ui";

export default async function Integrations() {
  return (
    <ContentLayout title="Integrations" icon="lucide:puzzle">
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

          {/* SSO Configuration - redirects to Profile */}
          <SsoLinkCard />

          {/* API Keys - redirects to Profile */}
          <ApiKeyLinkCard />
        </div>
      </div>
    </ContentLayout>
  );
}
