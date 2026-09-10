import { describe, expect, it, vi } from "vitest";

import type {
  LighthouseV2Configuration,
  LighthouseV2ProviderType,
  LighthouseV2SupportedModel,
} from "@/app/(prowler)/lighthouse/_types";

import { loadLighthouseV2ConnectedModels } from "./model-loading";

describe("loadLighthouseV2ConnectedModels", () => {
  it("loads models only for connected configurations and initializes the rest as empty", async () => {
    // Given
    const openAIModel = model("gpt-5.5");
    const loadModels = vi.fn(async (providerType: LighthouseV2ProviderType) => {
      if (providerType === "openai-compatible") {
        return { error: "Connection failed", status: 400 };
      }

      return { data: [openAIModel] };
    });

    // When
    const result = await loadLighthouseV2ConnectedModels(
      [
        configuration("openai", true),
        configuration("bedrock", false),
        configuration("openai-compatible", false),
      ],
      loadModels,
    );

    // Then
    expect(loadModels).toHaveBeenCalledTimes(1);
    expect(loadModels).toHaveBeenCalledWith("openai");
    expect(result.modelsByProvider).toEqual({
      openai: [openAIModel],
      bedrock: [],
      "openai-compatible": [],
    });
    expect(result.failedModelProviders).toEqual([]);
  });

  it("reports model-loading failures only for connected configurations", async () => {
    // Given
    const loadModels = vi.fn(async (providerType: LighthouseV2ProviderType) => {
      if (providerType === "bedrock") {
        return { error: "Bedrock models unavailable", status: 503 };
      }

      throw new Error(`Disconnected provider should not load: ${providerType}`);
    });

    // When
    const result = await loadLighthouseV2ConnectedModels(
      [
        configuration("openai", false),
        configuration("bedrock", true),
        configuration("openai-compatible", false),
      ],
      loadModels,
    );

    // Then
    expect(loadModels).toHaveBeenCalledTimes(1);
    expect(loadModels).toHaveBeenCalledWith("bedrock");
    expect(result.modelsByProvider).toEqual({
      openai: [],
      bedrock: [],
      "openai-compatible": [],
    });
    expect(result.failedModelProviders).toEqual(["bedrock"]);
  });

  it("dedupes provider types and treats null connection state as disconnected", async () => {
    // Given
    const openAIModel = model("gpt-5.5");
    const loadModels = vi.fn(async () => ({ data: [openAIModel] }));

    // When
    const result = await loadLighthouseV2ConnectedModels(
      [
        configuration("openai", true),
        { ...configuration("openai", true), id: "config-openai-2" },
        { ...configuration("bedrock", false), connected: null },
      ],
      loadModels,
    );

    // Then
    expect(loadModels).toHaveBeenCalledTimes(1);
    expect(loadModels).toHaveBeenCalledWith("openai");
    expect(result.modelsByProvider.openai).toEqual([openAIModel]);
    expect(result.modelsByProvider.bedrock).toEqual([]);
  });
});

function configuration(
  providerType: LighthouseV2ProviderType,
  connected: boolean,
): LighthouseV2Configuration {
  return {
    id: `config-${providerType}`,
    providerType,
    baseUrl:
      providerType === "openai-compatible" ? "https://example.com" : null,
    defaultModel: null,
    businessContext: "Production account",
    connected,
    connectionLastCheckedAt: null,
    insertedAt: "2026-06-24T09:00:00Z",
    updatedAt: "2026-06-24T10:00:00Z",
  };
}

function model(id: string): LighthouseV2SupportedModel {
  return {
    id,
    name: id,
    maxInputTokens: null,
    maxOutputTokens: null,
    supportsFunctionCalling: true,
    supportsVision: false,
    supportsReasoning: true,
  };
}
