import { describe, expect, it } from "vitest";

import {
  buildLighthouseV2ModelSelectionValue,
  parseLighthouseV2ModelSelectionValue,
} from "./model-selection";

describe("model-selection value codec", () => {
  it("round-trips a provider and model id", () => {
    // Given
    const value = buildLighthouseV2ModelSelectionValue("openai", "gpt-5.1");

    // When
    const selection = parseLighthouseV2ModelSelectionValue(value);

    // Then
    expect(value).toBe("openai:gpt-5.1");
    expect(selection).toEqual({ providerType: "openai", modelId: "gpt-5.1" });
  });

  it("keeps colons inside Bedrock model ids by splitting on the first colon only", () => {
    // Given
    const value = buildLighthouseV2ModelSelectionValue(
      "bedrock",
      "anthropic.claude-3-sonnet-20240229-v1:0",
    );

    // When
    const selection = parseLighthouseV2ModelSelectionValue(value);

    // Then
    expect(selection).toEqual({
      providerType: "bedrock",
      modelId: "anthropic.claude-3-sonnet-20240229-v1:0",
    });
  });

  it("rejects values without a known provider or model id", () => {
    // Then
    expect(parseLighthouseV2ModelSelectionValue("")).toBeNull();
    expect(parseLighthouseV2ModelSelectionValue("gpt-5.1")).toBeNull();
    expect(parseLighthouseV2ModelSelectionValue(":gpt-5.1")).toBeNull();
    expect(parseLighthouseV2ModelSelectionValue("unknown:gpt-5.1")).toBeNull();
    expect(parseLighthouseV2ModelSelectionValue("openai:")).toBeNull();
  });
});
