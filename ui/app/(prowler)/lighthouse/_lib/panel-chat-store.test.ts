import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/app/(prowler)/lighthouse/_actions", () => ({
  createLighthouseV2Session: vi.fn(),
  getLighthouseV2Messages: vi.fn(),
  sendLighthouseV2Message: vi.fn(),
  updateLighthouseV2Configuration: vi.fn(),
}));

import type { LighthouseChatConfig } from "./chat-store";
import {
  flushPendingPanelChatMessage,
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

  it("should submit a message queued before the panel chat store is created", () => {
    // Given
    requestPanelChatMessage("Analyze this finding");
    const store = getOrCreatePanelChatStore(EMPTY_CHAT_CONFIG);
    const submitMessage = vi
      .spyOn(store.getState(), "submitMessage")
      .mockResolvedValue();

    // When
    flushPendingPanelChatMessage();

    // Then
    expect(submitMessage).toHaveBeenCalledWith(
      "Analyze this finding",
      undefined,
    );
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
});
