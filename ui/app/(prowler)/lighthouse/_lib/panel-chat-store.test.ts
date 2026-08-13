import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/app/(prowler)/lighthouse/_actions", () => ({
  createLighthouseV2Session: vi.fn(),
  getLighthouseV2Messages: vi.fn(),
  sendLighthouseV2Message: vi.fn(),
  updateLighthouseV2Configuration: vi.fn(),
}));

import { getSkillById } from "@/lib/lighthouse/skills/registry";

import type { LighthouseChatConfig } from "./chat-store";
import {
  flushPendingPanelChatMessage,
  getOrCreatePanelChatStore,
  requestPanelChatMessage,
  requestPanelSkillLaunch,
  resetPanelChatStoreForTests,
} from "./panel-chat-store";

const EMPTY_CHAT_CONFIG: LighthouseChatConfig = {
  configurations: [],
  modelsByProvider: {
    openai: [],
    bedrock: [],
    "openai-compatible": [],
  },
  supportedProviders: [],
};

describe("panel chat message request", () => {
  afterEach(() => {
    resetPanelChatStoreForTests();
  });

  it("should start a new chat before submitting through an existing store", () => {
    // Given
    const store = getOrCreatePanelChatStore(EMPTY_CHAT_CONFIG);
    store.setState({ activeSessionId: "existing-session" });
    const resetToNewChat = vi.spyOn(store.getState(), "resetToNewChat");
    const submitMessage = vi
      .spyOn(store.getState(), "submitMessage")
      .mockResolvedValue();

    // When
    requestPanelChatMessage("Analyze this finding");

    // Then
    expect(resetToNewChat).toHaveBeenCalledOnce();
    expect(submitMessage).toHaveBeenCalledWith(
      "Analyze this finding",
      undefined,
      undefined,
    );
    expect(resetToNewChat.mock.invocationCallOrder[0]).toBeLessThan(
      submitMessage.mock.invocationCallOrder[0],
    );
  });

  it("should submit a skill launch as a message titled after the skill", () => {
    // Given
    const store = getOrCreatePanelChatStore(EMPTY_CHAT_CONFIG);
    const submitMessage = vi
      .spyOn(store.getState(), "submitMessage")
      .mockResolvedValue();
    const skill = getSkillById("triage-decision");
    if (!skill) throw new Error("Expected skill definition");

    // When
    requestPanelSkillLaunch(skill);

    // Then
    expect(submitMessage).toHaveBeenCalledWith(
      "Triage Decision",
      undefined,
      skill,
    );
  });

  it("should queue a skill launch until the panel store exists, then flush it", () => {
    // Given: no store yet — the panel has not been opened/configured
    const skill = getSkillById("systemic-scope");
    if (!skill) throw new Error("Expected skill definition");
    requestPanelSkillLaunch(skill);

    // When: the panel store is created later and the queue flushes
    const store = getOrCreatePanelChatStore(EMPTY_CHAT_CONFIG);
    const submitMessage = vi
      .spyOn(store.getState(), "submitMessage")
      .mockResolvedValue();
    flushPendingPanelChatMessage();

    // Then
    expect(submitMessage).toHaveBeenCalledWith(
      "Systemic Scope",
      undefined,
      skill,
    );
  });

  it("should cancel an initial submission before sending a contextual request", () => {
    // Given: the store is still creating its first session
    const store = getOrCreatePanelChatStore(EMPTY_CHAT_CONFIG);
    store.setState({ isSubmitting: true });
    const resetToNewChat = vi.spyOn(store.getState(), "resetToNewChat");
    const submitMessage = vi
      .spyOn(store.getState(), "submitMessage")
      .mockResolvedValue();

    // When
    requestPanelChatMessage("Analyze this finding");

    // Then
    expect(resetToNewChat).toHaveBeenCalledOnce();
    expect(submitMessage).toHaveBeenCalledWith(
      "Analyze this finding",
      undefined,
      undefined,
    );
  });
});
