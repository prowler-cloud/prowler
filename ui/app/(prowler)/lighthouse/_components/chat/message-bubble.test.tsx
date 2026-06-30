import { render, screen } from "@testing-library/react";
import { type ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import {
  LIGHTHOUSE_V2_MESSAGE_ROLE,
  LIGHTHOUSE_V2_PART_TYPE,
  type LighthouseV2Message,
} from "@/app/(prowler)/lighthouse/_types";

import { MessageBubble } from "./message-bubble";

vi.mock("streamdown", () => ({
  Streamdown: ({ children }: { children: ReactNode }) => <>{children}</>,
  defaultRehypePlugins: { katex: undefined, harden: undefined },
}));

describe("MessageBubble", () => {
  it("should render assistant text and tool calls in persisted part order", () => {
    // Given
    const orderedMessage = buildAssistantMessage([
      textPart("part-1", "Voy a buscar los findings por severidad"),
      toolCallPart("part-2", "prowler_app_search_security_findings"),
      textPart("part-3", "Ahora voy a buscar en los criticos"),
    ]);

    // When
    render(<MessageBubble message={orderedMessage} />);

    // Then
    const firstText = screen.getByText(
      "Voy a buscar los findings por severidad",
    );
    const toolCall = screen.getByRole("button", {
      name: /Used Search security findings/,
    });
    const secondText = screen.getByText("Ahora voy a buscar en los criticos");

    expect(isBefore(firstText, toolCall)).toBe(true);
    expect(isBefore(toolCall, secondText)).toBe(true);
  });
});

function isBefore(first: HTMLElement, second: HTMLElement): boolean {
  return Boolean(
    first.compareDocumentPosition(second) & Node.DOCUMENT_POSITION_FOLLOWING,
  );
}

function buildAssistantMessage(
  parts: LighthouseV2Message["parts"],
): LighthouseV2Message {
  return {
    id: "message-1",
    role: LIGHTHOUSE_V2_MESSAGE_ROLE.ASSISTANT,
    model: null,
    tokenUsage: null,
    insertedAt: "2026-06-25T10:00:00Z",
    parts,
  };
}

function textPart(
  id: string,
  text: string,
): LighthouseV2Message["parts"][number] {
  return {
    id,
    type: LIGHTHOUSE_V2_PART_TYPE.TEXT,
    content: { text },
    toolCallOutcome: null,
    insertedAt: "2026-06-25T10:00:00Z",
    updatedAt: "2026-06-25T10:00:00Z",
  };
}

function toolCallPart(
  id: string,
  toolName: string,
): LighthouseV2Message["parts"][number] {
  return {
    id,
    type: LIGHTHOUSE_V2_PART_TYPE.TOOL_CALL,
    content: {
      tool_call_id: id,
      tool_name: toolName,
      arguments: null,
      result: null,
      outcome: "success",
    },
    toolCallOutcome: "success",
    insertedAt: "2026-06-25T10:00:01Z",
    updatedAt: "2026-06-25T10:00:01Z",
  };
}
