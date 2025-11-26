import { redirect } from "next/navigation";

import {
  getLighthouseProvidersConfig,
  isLighthouseConfigured,
} from "@/actions/lighthouse/lighthouse";
import { LighthouseIcon } from "@/components/icons/Icons";
import { Chat } from "@/components/lighthouse";
import { ContentLayout } from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function AIChatbot() {
  const hasConfig = await isLighthouseConfigured();

  if (!hasConfig) {
    return redirect("/lighthouse/config");
  }

  // Fetch provider configuration with default models
  const providersConfig = await getLighthouseProvidersConfig();

  // Handle errors or missing configuration
  if (providersConfig.errors || !providersConfig.providers) {
    return redirect("/lighthouse/config");
  }

  return (
    <ContentLayout title="Lighthouse AI" icon={<LighthouseIcon />}>
      <Chat
        hasConfig={hasConfig}
        providers={providersConfig.providers}
        defaultProviderId={providersConfig.defaultProviderId}
        defaultModelId={providersConfig.defaultModelId}
      />
    </ContentLayout>
  );
}
