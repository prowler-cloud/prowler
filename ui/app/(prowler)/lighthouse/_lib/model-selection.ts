import {
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  type LighthouseV2ProviderType,
} from "@/app/(prowler)/lighthouse/_types";

export interface LighthouseV2ModelSelection {
  providerType: LighthouseV2ProviderType;
  modelId: string;
}

// Encodes a provider + model into a single combobox option value. The value is
// kept human-readable (no encoding) so the combobox search matches the model id
// the user types. Bedrock model ids can contain ":" (e.g. "...-v1:0"), so the
// parser splits on the FIRST ":" only.
export function buildLighthouseV2ModelSelectionValue(
  providerType: LighthouseV2ProviderType,
  modelId: string,
) {
  return `${providerType}:${modelId}`;
}

export function parseLighthouseV2ModelSelectionValue(
  value: string,
): LighthouseV2ModelSelection | null {
  const separatorIndex = value.indexOf(":");
  if (separatorIndex <= 0) return null;

  const providerType = value.slice(0, separatorIndex);
  if (!isLighthouseV2ProviderType(providerType)) return null;

  const modelId = value.slice(separatorIndex + 1);
  if (!modelId) return null;

  return { providerType, modelId };
}

function isLighthouseV2ProviderType(
  value: string,
): value is LighthouseV2ProviderType {
  return (
    value === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI ||
    value === LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK ||
    value === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE
  );
}
