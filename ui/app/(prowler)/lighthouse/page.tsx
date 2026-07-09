import { redirect } from "next/navigation";

import {
  getLighthouseProvidersConfig,
  isLighthouseConfigured,
} from "@/actions/lighthouse-v1/lighthouse";
import {
  getLighthouseV2Configurations,
  getLighthouseV2Messages,
  getLighthouseV2SupportedModels,
  getLighthouseV2SupportedProviders,
} from "@/app/(prowler)/lighthouse/_actions";
import { LighthouseV2ChatPage } from "@/app/(prowler)/lighthouse/_components/chat";
import { LighthouseV2NavigationModeSync } from "@/app/(prowler)/lighthouse/_components/navigation";
import { loadLighthouseV2ConnectedModels } from "@/app/(prowler)/lighthouse/_lib/model-loading";
import { LighthouseIcon } from "@/components/icons/Icons";
import { Chat } from "@/components/lighthouse-v1";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";
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
    const [configurationsResult, supportedProvidersResult] = await Promise.all([
      getLighthouseV2Configurations(),
      getLighthouseV2SupportedProviders(),
    ]);
    const configurations =
      "data" in configurationsResult ? configurationsResult.data : [];
    const supportedProviders =
      "data" in supportedProvidersResult ? supportedProvidersResult.data : [];
    const connectedConfigurations = configurations.filter(
      (configuration) => configuration.connected === true,
    );

    if (connectedConfigurations.length === 0) {
      return redirect(LIGHTHOUSE_ROUTE.SETTINGS);
    }

    const { modelsByProvider, failedModelProviders } =
      await loadLighthouseV2ConnectedModels(
        configurations,
        getLighthouseV2SupportedModels,
      );
    // Surface (rather than silently swallow to []) connected providers whose
    // models failed to load, so their empty list reads as a real backend
    // failure. Disconnected providers are never fetched (see model-loading.ts).
    const modelsError =
      failedModelProviders.length > 0
        ? `Could not load available models for: ${failedModelProviders.join(", ")}. Try again shortly.`
        : undefined;

    const initialMessages = activeSessionId
      ? await getLighthouseV2Messages(activeSessionId)
      : { data: [] };
    // Treat the ?session= id as valid when its messages load (you can't fetch
    // messages for a non-existent session, so this is the authoritative
    // "session exists" check). A stale/deleted id fails here and is dropped so
    // the client starts fresh instead of sending against a dead session.
    const sessionLoaded = Boolean(activeSessionId) && "data" in initialMessages;
    const validSessionId = sessionLoaded ? activeSessionId : undefined;
    const chatMessages =
      sessionLoaded && "data" in initialMessages ? initialMessages.data : [];
    const chatRouteKey = validSessionId ?? initialPrompt ?? "new";

    return (
      <ContentLayout title="Lighthouse AI" icon={<LighthouseIcon />}>
        <LighthouseV2NavigationModeSync />
        {/* [contain:layout] traps streamdown's fixed fullscreen overlay inside
            the chat area so it never covers the sidebar or navbar. */}
        <div className="h-[calc(100dvh-6.5rem)] min-h-0 [contain:layout]">
          <LighthouseV2ChatPage
            key={chatRouteKey}
            configurations={configurations}
            modelsByProvider={modelsByProvider}
            supportedProviders={supportedProviders}
            initialSessionId={validSessionId}
            initialMessages={chatMessages}
            initialPrompt={initialPrompt}
            initialError={modelsError}
          />
        </div>
      </ContentLayout>
    );
  }

  const hasConfig = await isLighthouseConfigured();

  if (!hasConfig) {
    return redirect(LIGHTHOUSE_ROUTE.SETTINGS);
  }

  // Fetch provider configuration with default models
  const providersConfig = await getLighthouseProvidersConfig();

  // Handle errors or missing configuration
  if (providersConfig.errors || !providersConfig.providers) {
    return redirect(LIGHTHOUSE_ROUTE.SETTINGS);
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
