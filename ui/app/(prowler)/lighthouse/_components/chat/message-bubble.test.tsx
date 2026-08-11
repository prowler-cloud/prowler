import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { type ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import {
  LIGHTHOUSE_V2_MESSAGE_ROLE,
  LIGHTHOUSE_V2_PART_TYPE,
  type LighthouseV2Message,
} from "@/app/(prowler)/lighthouse/_types";

import { MessageBubble } from "./message-bubble";

const { submitFeedbackMock } = vi.hoisted(() => ({
  submitFeedbackMock: vi.fn(),
}));

vi.mock("@/app/(prowler)/lighthouse/_actions", () => ({
  submitLighthouseV2RunFeedback: submitFeedbackMock,
}));

vi.mock("streamdown", () => ({
  Streamdown: ({ children }: { children: ReactNode }) => {
    const text = String(children);
    if (text.includes("very-wide-header")) {
      return (
        <table>
          <caption>Wide markdown table</caption>
          <tbody>
            <tr>
              <td>{text}</td>
            </tr>
          </tbody>
        </table>
      );
    }

    if (text.includes("graph TD")) {
      // Mirrors streamdown's real mermaid DOM: pan/zoom wrapper + inline max-width on the svg
      return (
        <div data-streamdown="mermaid-block">
          <div className="my-4 overflow-hidden">
            <div role="application">
              <div aria-label="Mermaid chart" role="img">
                <svg aria-hidden="true" style={{ maxWidth: "1024px" }} />
              </div>
            </div>
          </div>
        </div>
      );
    }

    return <>{children}</>;
  },
  defaultRehypePlugins: { katex: undefined, harden: undefined },
}));

describe("MessageBubble", () => {
  it("should never render the agent-facing context block for user messages", () => {
    // Given
    const userMessage: LighthouseV2Message = {
      id: "message-user-1",
      role: LIGHTHOUSE_V2_MESSAGE_ROLE.USER,
      model: null,
      tokenUsage: null,
      insertedAt: "2026-06-25T10:00:00Z",
      parts: [
        {
          id: "part-user-1",
          type: LIGHTHOUSE_V2_PART_TYPE.TEXT,
          content: {
            text: "[PROWLER_UI_CONTEXT_V1]\nmetadata\n[/PROWLER_UI_CONTEXT_V1]\n\nQuestion",
            display_text: "Question",
          },
          toolCallOutcome: null,
          insertedAt: "2026-06-25T10:00:00Z",
          updatedAt: "2026-06-25T10:00:00Z",
        },
      ],
    };

    // When
    render(<MessageBubble message={userMessage} />);

    // Then
    expect(screen.getByText("Question")).toBeInTheDocument();
    expect(screen.queryByText(/PROWLER_UI_CONTEXT_V1/)).not.toBeInTheDocument();
  });

  it("should render persisted user context as a read-only historical badge", () => {
    // Given
    const userMessage: LighthouseV2Message = {
      id: "message-user-context",
      role: LIGHTHOUSE_V2_MESSAGE_ROLE.USER,
      model: null,
      tokenUsage: null,
      insertedAt: "2026-06-25T10:00:00Z",
      parts: [
        {
          id: "part-user-context",
          type: LIGHTHOUSE_V2_PART_TYPE.TEXT,
          content: {
            text: "technical prompt",
            display_text: "Question",
            ui_context: {
              schema_version: 1,
              transport: "inline",
              items: [
                {
                  kind: "page",
                  id: "findings",
                  source: "automatic",
                  scope_key: "findings:/findings",
                  label: "Findings",
                  path: "/findings",
                },
                {
                  kind: "finding",
                  id: "finding-1",
                  source: "focused",
                  scope_key: "findings:/findings",
                  label: "Focused finding",
                  finding_id: "finding-1",
                  check_id: "aws_s3_bucket_public_access",
                },
              ],
            },
          },
          toolCallOutcome: null,
          insertedAt: "2026-06-25T10:00:00Z",
          updatedAt: "2026-06-25T10:00:00Z",
        },
      ],
    };

    // When
    render(<MessageBubble message={userMessage} />);

    // Then
    expect(screen.getByText("@ Findings · Detail")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Remove Findings context/ }),
    ).not.toBeInTheDocument();
  });

  it("should render assistant text and tool calls in persisted part order", () => {
    // Given
    const orderedMessage = buildAssistantMessage([
      textPart("part-1", "Voy a buscar los findings por severidad"),
      toolCallPart("part-2", "prowler_search_security_findings"),
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

  it("should submit passive feedback for a completed assistant outcome", async () => {
    submitFeedbackMock.mockResolvedValue({ data: true });
    const message = {
      ...buildAssistantMessage([textPart("part-1", "Done")]),
      run: {
        id: "run-1",
        status: "completed" as const,
        terminalCode: null,
        hasAssistantMessage: true,
        feedbackRating: null,
      },
    };

    render(<MessageBubble message={message} sessionId="session-1" />);
    fireEvent.click(
      screen.getByRole("button", { name: "Mark outcome as not helpful" }),
    );

    await waitFor(() => expect(submitFeedbackMock).toHaveBeenCalledOnce());
    expect(submitFeedbackMock).toHaveBeenCalledWith({
      sessionId: "session-1",
      runId: "run-1",
      rating: "down",
      idempotencyKey: expect.any(String),
    });
    const selectedButton = screen.getByRole("button", {
      name: "Mark outcome as not helpful",
    });
    expect(selectedButton).toHaveAttribute("aria-pressed", "true");
    expect(selectedButton).toHaveClass("bg-button-primary", "text-black");
  });

  it("should expose feedback for failed outcomes without an assistant message", () => {
    const message: LighthouseV2Message = {
      id: "message-user-failed",
      role: LIGHTHOUSE_V2_MESSAGE_ROLE.USER,
      model: null,
      tokenUsage: null,
      insertedAt: "2026-06-25T10:00:00Z",
      parts: [textPart("part-user", "Run this check")],
      run: {
        id: "run-failed",
        status: "failed",
        terminalCode: "llm_error",
        hasAssistantMessage: false,
        feedbackRating: null,
      },
    };

    render(<MessageBubble message={message} sessionId="session-1" />);

    expect(
      screen.getByRole("button", { name: "Mark outcome as helpful" }),
    ).toBeInTheDocument();
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
