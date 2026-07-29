import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/app/(prowler)/lighthouse/_actions", () => ({
  createLighthouseV2Session: vi.fn(),
  getLighthouseV2Messages: vi.fn(),
  sendLighthouseV2Message: vi.fn(),
  updateLighthouseV2Configuration: vi.fn(),
}));

import type { LighthouseChatConfig } from "./chat-store";
import {
  getOrCreatePanelChatStore,
  requestPanelChatMessage,
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
    );
    expect(resetToNewChat.mock.invocationCallOrder[0]).toBeLessThan(
      submitMessage.mock.invocationCallOrder[0],
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
    );
  });
});
