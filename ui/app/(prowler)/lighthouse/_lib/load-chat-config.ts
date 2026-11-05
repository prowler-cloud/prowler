import {
  getLighthouseV2Configurations,
  getLighthouseV2SupportedModels,
  getLighthouseV2SupportedProviders,
} from "@/app/(prowler)/lighthouse/_actions";
import type { LighthouseChatConfig } from "@/app/(prowler)/lighthouse/_lib/chat-store";
import { loadLighthouseV2ConnectedModels } from "@/app/(prowler)/lighthouse/_lib/model-loading";

export const LIGHTHOUSE_CHAT_CONFIG_STATUS = {
  ERROR: "error",
  NOT_CONFIGURED: "not-configured",
  READY: "ready",
} as const;

interface LighthouseChatConfigError {
  status: typeof LIGHTHOUSE_CHAT_CONFIG_STATUS.ERROR;
  message: string;
}

interface LighthouseChatConfigNotConfigured {
  status: typeof LIGHTHOUSE_CHAT_CONFIG_STATUS.NOT_CONFIGURED;
}

interface LighthouseChatConfigReady {
  status: typeof LIGHTHOUSE_CHAT_CONFIG_STATUS.READY;
  config: LighthouseChatConfig;
  modelsError?: string;
}

export type LighthouseChatConfigResult =
  | LighthouseChatConfigError
  | LighthouseChatConfigNotConfigured
  | LighthouseChatConfigReady;

// Shared by the /lighthouse server page and the client panel: both need the
// same configurations + providers + connected-models bundle. Server actions
// are callable from either context. Rejections propagate to the caller.
export async function loadLighthouseChatConfig(): Promise<LighthouseChatConfigResult> {
  const [configurationsResult, supportedProvidersResult] = await Promise.all([
    getLighthouseV2Configurations(),
    getLighthouseV2SupportedProviders(),
  ]);
  if ("error" in configurationsResult) {
    return {
      status: LIGHTHOUSE_CHAT_CONFIG_STATUS.ERROR,
      message: configurationsResult.error,
    };
  }
  if ("error" in supportedProvidersResult) {
    return {
      status: LIGHTHOUSE_CHAT_CONFIG_STATUS.ERROR,
      message: supportedProvidersResult.error,
    };
  }

  const configurations = configurationsResult.data;
  const hasConnectedProvider = configurations.some(
    (configuration) => configuration.connected === true,
  );
  if (!hasConnectedProvider) {
    return { status: LIGHTHOUSE_CHAT_CONFIG_STATUS.NOT_CONFIGURED };
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

  return {
    status: LIGHTHOUSE_CHAT_CONFIG_STATUS.READY,
    config: {
      configurations,
      modelsByProvider,
      supportedProviders: supportedProvidersResult.data,
    },
    modelsError,
  };
}
