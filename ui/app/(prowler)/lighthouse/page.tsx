import { redirect } from "next/navigation";

import {
  getLighthouseProvidersConfig,
  isLighthouseConfigured,
} from "@/actions/lighthouse-v1/lighthouse";
import {
  getLighthouseV2Configurations,
  getLighthouseV2Messages,
  getLighthouseV2Sessions,
  getLighthouseV2SupportedModels,
} from "@/actions/lighthouse-v2/lighthouse-v2";
import { LighthouseIcon } from "@/components/icons/Icons";
import { Chat } from "@/components/lighthouse-v1";
import { LighthouseV2ChatPage } from "@/components/lighthouse-v2/chat";
import { ContentLayout } from "@/components/ui";
import { isCloud } from "@/lib/shared/env";
import type {
  LighthouseV2ProviderType,
  LighthouseV2SupportedModel,
} from "@/types/lighthouse-v2";

export const dynamic = "force-dynamic";

export default async function AIChatbot({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const initialPrompt =
    typeof params.prompt === "string" ? params.prompt : undefined;
  const activeSessionId =
    typeof params.session === "string" ? params.session : undefined;

  if (isCloud()) {
    const [configurationsResult, sessionsResult] = await Promise.all([
      getLighthouseV2Configurations(),
      getLighthouseV2Sessions(),
    ]);

    const configurations =
      "data" in configurationsResult ? configurationsResult.data : [];
    const connectedConfigurations = configurations.filter(
      (configuration) => configuration.connected === true,
    );

    if (connectedConfigurations.length === 0) {
      return redirect("/lighthouse/config");
    }

    const modelsEntries = await Promise.all(
      configurations.map(async (configuration) => {
        const result = await getLighthouseV2SupportedModels(
          configuration.providerType,
        );
        return [
          configuration.providerType,
          "data" in result ? result.data : [],
        ] as const satisfies readonly [
          LighthouseV2ProviderType,
          LighthouseV2SupportedModel[],
        ];
      }),
    );
    const modelsByProvider = Object.fromEntries(modelsEntries) as Record<
      LighthouseV2ProviderType,
      LighthouseV2SupportedModel[]
    >;
    const initialMessages =
      activeSessionId && "data" in sessionsResult
        ? await getLighthouseV2Messages(activeSessionId)
        : { data: [] };

    return (
      <ContentLayout title="Lighthouse AI" icon={<LighthouseIcon />}>
        <div className="-mx-6 -my-4 h-[calc(100dvh-4.5rem)] sm:-mx-8">
          <LighthouseV2ChatPage
            configurations={configurations}
            modelsByProvider={modelsByProvider}
            sessions={"data" in sessionsResult ? sessionsResult.data : []}
            initialSessionId={activeSessionId}
            initialMessages={
              "data" in initialMessages ? initialMessages.data : []
            }
            initialPrompt={initialPrompt}
          />
        </div>
      </ContentLayout>
    );
  }

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
      <div className="-mx-6 -my-4 h-[calc(100dvh-4.5rem)] sm:-mx-8">
        <Chat
          hasConfig={hasConfig}
          providers={providersConfig.providers}
          defaultProviderId={providersConfig.defaultProviderId}
          defaultModelId={providersConfig.defaultModelId}
          initialPrompt={initialPrompt}
        />
      </div>
    </ContentLayout>
  );
}
