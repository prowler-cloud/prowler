import { describe, expect, it } from "vitest";

import { render } from "@/__tests__/render-browser";
import {
  LIGHTHOUSE_V2_MESSAGE_ROLE,
  LIGHTHOUSE_V2_PART_TYPE,
  type LighthouseV2Message,
} from "@/app/(prowler)/lighthouse/_types";

import { MessageBubble } from "./message-bubble";

describe("MessageBubble", () => {
  it("should wrap long user text inside the message bubble", async () => {
    // Given
    const longText = "a".repeat(500);
    const userMessage: LighthouseV2Message = {
      id: "message-user-long-text",
      role: LIGHTHOUSE_V2_MESSAGE_ROLE.USER,
      model: null,
      tokenUsage: null,
      insertedAt: "2026-06-25T10:00:00Z",
      parts: [
        {
          id: "part-user-long-text",
          type: LIGHTHOUSE_V2_PART_TYPE.TEXT,
          content: { text: longText },
          toolCallOutcome: null,
          insertedAt: "2026-06-25T10:00:00Z",
          updatedAt: "2026-06-25T10:00:00Z",
        },
      ],
    };

    // When
    const { getByText } = await render(
      <div style={{ width: 320 }}>
        <MessageBubble message={userMessage} />
      </div>,
    );
    const messageText = getByText(longText).element();

    // Then
    expect(messageText.scrollWidth).toBeLessThanOrEqual(
      messageText.clientWidth,
    );
  });
});
