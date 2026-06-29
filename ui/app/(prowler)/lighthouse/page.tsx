import { redirect } from "next/navigation";

import {
  getLighthouseProvidersConfig,
  isLighthouseConfigured,
} from "@/actions/lighthouse-v1/lighthouse";
import {
  getLighthouseV2Configurations,
  getLighthouseV2Messages,
  getLighthouseV2Session,
  getLighthouseV2SupportedModels,
  getLighthouseV2TenantConfiguration,
} from "@/app/(prowler)/lighthouse/_actions";
import { LighthouseV2ChatPage } from "@/app/(prowler)/lighthouse/_components/chat";
import { LighthouseV2NavigationModeSync } from "@/app/(prowler)/lighthouse/_components/navigation";
import { buildLighthouseV2StreamUrl } from "@/app/(prowler)/lighthouse/_lib/stream-url";
import type {
  LighthouseV2ProviderType,
  LighthouseV2SupportedModel,
} from "@/app/(prowler)/lighthouse/_types";
import { LighthouseIcon } from "@/components/icons/Icons";
import { Chat } from "@/components/lighthouse-v1";
import { ContentLayout } from "@/components/ui";
import { isCloud } from "@/lib/shared/env";

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
    const [configurationsResult, tenantConfigurationResult] = await Promise.all(
      [getLighthouseV2Configurations(), getLighthouseV2TenantConfiguration()],
    );
    const configurations =
      "data" in configurationsResult ? configurationsResult.data : [];
    const connectedConfigurations = configurations.filter(
      (configuration) => configuration.connected === true,
    );

    if (connectedConfigurations.length === 0) {
      return redirect("/lighthouse/settings");
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
    const [initialMessages, activeSession] = activeSessionId
      ? await Promise.all([
          getLighthouseV2Messages(activeSessionId),
          getLighthouseV2Session(activeSessionId),
        ])
      : [{ data: [] }, undefined];
    const initialActiveTaskId =
      activeSession && "data" in activeSession
        ? (activeSession.data.activeTaskId ?? null)
        : null;
    const initialStreamUrl =
      activeSessionId && initialActiveTaskId
        ? buildLighthouseV2StreamUrl(activeSessionId)
        : undefined;
    const chatRouteKey = activeSessionId ?? initialPrompt ?? "new";

    return (
      <ContentLayout title="Lighthouse AI" icon={<LighthouseIcon />}>
        <LighthouseV2NavigationModeSync />
        <div className="h-[calc(100dvh-6.5rem)] min-h-0">
          <LighthouseV2ChatPage
            key={chatRouteKey}
            configurations={configurations}
            modelsByProvider={modelsByProvider}
            tenantConfiguration={
              "data" in tenantConfigurationResult
                ? tenantConfigurationResult.data
                : undefined
            }
            initialSessionId={activeSessionId}
            initialMessages={
              "data" in initialMessages ? initialMessages.data : []
            }
            initialActiveTaskId={initialActiveTaskId}
            initialStreamUrl={initialStreamUrl}
            initialPrompt={initialPrompt}
          />
        </div>
      </ContentLayout>
    );
  }

  const hasConfig = await isLighthouseConfigured();

  if (!hasConfig) {
    return redirect("/lighthouse/settings");
  }

  // Fetch provider configuration with default models
  const providersConfig = await getLighthouseProvidersConfig();

  // Handle errors or missing configuration
  if (providersConfig.errors || !providersConfig.providers) {
    return redirect("/lighthouse/settings");
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
