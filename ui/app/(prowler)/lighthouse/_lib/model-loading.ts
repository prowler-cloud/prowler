import {
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  type LighthouseV2Configuration,
  type LighthouseV2ProviderType,
  type LighthouseV2SupportedModel,
} from "@/app/(prowler)/lighthouse/_types";

interface LighthouseV2SupportedModelsSuccess {
  data: LighthouseV2SupportedModel[];
}

interface LighthouseV2SupportedModelsFailure {
  error: string;
  errors?: unknown[];
  status?: number;
}

type LighthouseV2SupportedModelsResult =
  | LighthouseV2SupportedModelsSuccess
  | LighthouseV2SupportedModelsFailure;

type LoadLighthouseV2SupportedModels = (
  providerType: LighthouseV2ProviderType,
) => Promise<LighthouseV2SupportedModelsResult>;

interface LighthouseV2ConnectedModelsResult {
  modelsByProvider: Record<
    LighthouseV2ProviderType,
    LighthouseV2SupportedModel[]
  >;
  failedModelProviders: LighthouseV2ProviderType[];
}

export function createEmptyLighthouseV2ModelsByProvider(): Record<
  LighthouseV2ProviderType,
  LighthouseV2SupportedModel[]
> {
  return {
    [LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI]: [],
    [LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK]: [],
    [LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE]: [],
  };
}

export async function loadLighthouseV2ConnectedModels(
  configurations: LighthouseV2Configuration[],
  loadModels: LoadLighthouseV2SupportedModels,
): Promise<LighthouseV2ConnectedModelsResult> {
  const modelsByProvider = createEmptyLighthouseV2ModelsByProvider();
  // Disconnected providers keep the [] pre-seed and never hit the models
  // endpoint, so they can't surface spurious load failures either.
  const connectedProviderTypes = Array.from(
    new Set(
      configurations
        .filter((configuration) => configuration.connected === true)
        .map((configuration) => configuration.providerType),
    ),
  );

  const modelsEntries = await Promise.all(
    connectedProviderTypes.map(async (providerType) => {
      const result = await loadModels(providerType);
      return [providerType, result] as const;
    }),
  );

  const failedModelProviders: LighthouseV2ProviderType[] = [];

  modelsEntries.forEach(([providerType, result]) => {
    if ("data" in result) {
      modelsByProvider[providerType] = result.data;
      return;
    }

    failedModelProviders.push(providerType);
  });

  return { modelsByProvider, failedModelProviders };
}
