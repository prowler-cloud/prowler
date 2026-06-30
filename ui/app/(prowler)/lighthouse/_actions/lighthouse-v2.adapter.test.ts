import { describe, expect, it } from "vitest";

import {
  buildLighthouseV2ConfigurationPayload,
  buildLighthouseV2ConfigurationUpdatePayload,
  buildLighthouseV2MessagePayload,
  mapLighthouseV2Configuration,
  mapLighthouseV2Message,
  mapLighthouseV2Model,
  mapLighthouseV2Provider,
  validateLighthouseV2ConfigurationInput,
} from "./lighthouse-v2.adapter";

describe("lighthouse-v2.adapter", () => {
  describe("when mapping Cloud JSON:API resources", () => {
    it("should map configuration attributes to UI fields", () => {
      // Given
      const resource: Parameters<typeof mapLighthouseV2Configuration>[0] = {
        id: "config-1",
        type: "lighthouse-ai-configurations",
        attributes: {
          provider_type: "bedrock",
          base_url: null,
          default_model: "anthropic.claude",
          business_context: "Production tenant",
          connected: true,
          connection_last_checked_at: "2026-06-24T10:00:00Z",
          inserted_at: "2026-06-24T09:00:00Z",
          updated_at: "2026-06-24T10:00:00Z",
        },
      };

      // When
      const config = mapLighthouseV2Configuration(resource);

      // Then
      expect(config).toEqual({
        id: "config-1",
        providerType: "bedrock",
        baseUrl: null,
        defaultModel: "anthropic.claude",
        businessContext: "Production tenant",
        connected: true,
        connectionLastCheckedAt: "2026-06-24T10:00:00Z",
        insertedAt: "2026-06-24T09:00:00Z",
        updatedAt: "2026-06-24T10:00:00Z",
      });
    });

    it("should map supported provider and model payloads", () => {
      // Given
      const provider = {
        id: "openai_compatible",
        type: "lighthouse-supported-providers",
        attributes: { name: "OpenAI Compatible" },
      };
      const model = {
        id: "gpt-5.5",
        type: "lighthouse-supported-models",
        attributes: {
          model_name: "GPT 5.5",
          max_input_tokens: 100000,
          max_output_tokens: 8192,
          supports_function_calling: true,
          supports_vision: false,
          supports_reasoning: true,
        },
      };

      // When / Then
      expect(mapLighthouseV2Provider(provider)).toEqual({
        id: "openai-compatible",
        name: "OpenAI Compatible",
      });
      expect(mapLighthouseV2Model(model)).toEqual({
        id: "gpt-5.5",
        name: "GPT 5.5",
        maxInputTokens: 100000,
        maxOutputTokens: 8192,
        supportsFunctionCalling: true,
        supportsVision: false,
        supportsReasoning: true,
      });
    });

    it("should map message parts from backend names", () => {
      // Given
      const resource: Parameters<typeof mapLighthouseV2Message>[0] = {
        id: "message-1",
        type: "lighthouse-messages",
        attributes: {
          role: "assistant",
          model: "gpt-5.5",
          token_usage: { input: 10 },
          inserted_at: "2026-06-24T10:01:00Z",
          parts: [
            {
              id: "part-1",
              type: "lighthouse-parts",
              attributes: {
                part_type: "text",
                content: { text: "Done" },
                tool_call_outcome: null,
                inserted_at: "2026-06-24T10:01:00Z",
                updated_at: "2026-06-24T10:01:00Z",
              },
            },
          ],
        },
      };

      // When
      const message = mapLighthouseV2Message(resource);

      // Then
      expect(message.parts[0]).toMatchObject({
        id: "part-1",
        type: "text",
        content: { text: "Done" },
      });
    });

    it("should give id-less parts stable fallback keys instead of empty strings", () => {
      // Given
      const resource: Parameters<typeof mapLighthouseV2Message>[0] = {
        id: "message-2",
        type: "lighthouse-messages",
        attributes: {
          role: "assistant",
          model: null,
          token_usage: null,
          inserted_at: "2026-06-24T10:02:00Z",
          parts: [
            { part_type: "text", content: { text: "one" } },
            { part_type: "text", content: { text: "two" } },
          ],
        },
      };

      // When
      const message = mapLighthouseV2Message(resource);

      // Then
      expect(message.parts.map((part) => part.id)).toEqual([
        "part-0",
        "part-1",
      ]);
    });

    it("should reject unknown provider ids at the adapter boundary", () => {
      // Given / When / Then
      expect(() =>
        mapLighthouseV2Provider({
          id: "totally-unknown-provider",
          type: "lighthouse-supported-providers",
          attributes: { name: "Mystery" },
        }),
      ).toThrow(/Unsupported Lighthouse v2 provider/);
    });
  });

  describe("when building Cloud payloads", () => {
    it("should use Cloud Bedrock credential keys", () => {
      // Given
      const input = {
        providerType: "bedrock" as const,
        credentials: {
          aws_access_key_id: "test-bedrock-access-key",
          aws_secret_access_key: "a".repeat(40),
          aws_region_name: "us-east-1",
        },
      };

      // When
      const payload = buildLighthouseV2ConfigurationPayload(input);

      // Then
      expect(payload.data).toMatchObject({
        type: "lighthouse-ai-configurations",
        attributes: {
          provider_type: "bedrock",
          credentials: {
            aws_access_key_id: "test-bedrock-access-key",
            aws_secret_access_key: "a".repeat(40),
            aws_region_name: "us-east-1",
          },
        },
      });
      expect(payload.data.attributes).not.toHaveProperty("default_model");
      expect(payload.data.attributes).not.toHaveProperty("business_context");
    });

    it("should serialize OpenAI-compatible configuration provider ids for the Cloud API", () => {
      // Given
      const input = {
        providerType: "openai-compatible" as const,
        credentials: { api_key: "provider-key" },
        baseUrl: "https://openrouter.ai/api/v1",
      };

      // When
      const payload = buildLighthouseV2ConfigurationPayload(input);

      // Then
      expect(payload.data.attributes).toMatchObject({
        provider_type: "openai_compatible",
        credentials: { api_key: "provider-key" },
        base_url: "https://openrouter.ai/api/v1",
      });
    });

    it("should serialize OpenAI-compatible message provider ids for the Cloud API", () => {
      // Given
      const input = {
        text: "Summarize critical findings",
        provider: "openai-compatible" as const,
        model: "openrouter/auto",
      };

      // When
      const payload = buildLighthouseV2MessagePayload(input);

      // Then
      expect(payload.data.attributes.provider).toBe("openai_compatible");
    });

    it("should build per-provider update payloads with default_model and business_context", () => {
      // When
      const payload = buildLighthouseV2ConfigurationUpdatePayload("config-1", {
        defaultModel: "anthropic.claude-4",
        businessContext: "Production tenant",
      });

      // Then
      expect(payload).toEqual({
        data: {
          type: "lighthouse-ai-configurations",
          id: "config-1",
          attributes: {
            default_model: "anthropic.claude-4",
            business_context: "Production tenant",
          },
        },
      });
    });

    it("should omit untouched fields from the update payload", () => {
      // When
      const payload = buildLighthouseV2ConfigurationUpdatePayload("config-1", {
        defaultModel: "gpt-5.1",
      });

      // Then
      expect(payload.data.attributes).toEqual({ default_model: "gpt-5.1" });
      expect(payload.data.attributes).not.toHaveProperty("business_context");
      expect(payload.data.attributes).not.toHaveProperty("credentials");
    });

    it("should require base_url for OpenAI-compatible configurations", () => {
      // Given
      const input = {
        providerType: "openai-compatible" as const,
        credentials: { api_key: "provider-key" },
      };

      // When
      const result = validateLighthouseV2ConfigurationInput(input);

      // Then
      expect(result).toEqual({
        success: false,
        error: "Base URL is required for OpenAI-compatible providers.",
      });
    });
  });
});
