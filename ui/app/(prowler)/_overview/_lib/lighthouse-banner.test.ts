import { describe, expect, it, vi } from "vitest";

import type {
  LighthouseV2Configuration,
  LighthouseV2ProviderType,
} from "@/app/(prowler)/lighthouse/_types";

import {
  getLighthouseOverviewBannerHref,
  resolveLighthouseOverviewBannerHref,
} from "./lighthouse-banner";

const NEW_CONVERSATION_CHAT_HREF =
  "/lighthouse?prompt=Find%20and%20guide%20me%20to%20remediate%20which%20actually%20matters.%20What%20do%20I%20have%20to%20do%20today%20to%20be%20secure%3F";

describe("resolveLighthouseOverviewBannerHref", () => {
  it("starts a new conversation with the remediation prompt when any v2 configuration is connected", () => {
    // Given / When
    const href = resolveLighthouseOverviewBannerHref([
      configuration("openai", false),
      configuration("bedrock", true),
    ]);

    // Then
    expect(href).toBe(NEW_CONVERSATION_CHAT_HREF);
  });

  it("routes to Lighthouse settings when no v2 configuration is connected", () => {
    // Given / When
    const href = resolveLighthouseOverviewBannerHref([
      configuration("openai", false),
      configuration("openai-compatible", null),
    ]);

    // Then
    expect(href).toBe("/lighthouse/settings");
  });
});

describe("getLighthouseOverviewBannerHref", () => {
  it("hides the banner outside cloud without loading configurations", async () => {
    // Given
    const loadConfigurations = vi.fn(async () => ({
      data: [configuration("openai", true)],
    }));

    // When
    const href = await getLighthouseOverviewBannerHref(
      false,
      loadConfigurations,
    );

    // Then
    expect(href).toBeNull();
    expect(loadConfigurations).not.toHaveBeenCalled();
  });

  it("hides the banner when configurations fail to load", async () => {
    // Given
    const loadConfigurations = vi.fn(async () => ({
      error: "Unauthorized",
      status: 401,
    }));

    // When
    const href = await getLighthouseOverviewBannerHref(
      true,
      loadConfigurations,
    );

    // Then
    expect(href).toBeNull();
  });

  it("resolves the banner href from loaded configurations in cloud", async () => {
    // Given
    const loadConfigurations = vi.fn(async () => ({
      data: [configuration("bedrock", true)],
    }));

    // When
    const href = await getLighthouseOverviewBannerHref(
      true,
      loadConfigurations,
    );

    // Then
    expect(href).toBe(NEW_CONVERSATION_CHAT_HREF);
  });
});

function configuration(
  providerType: LighthouseV2ProviderType,
  connected: LighthouseV2Configuration["connected"],
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
