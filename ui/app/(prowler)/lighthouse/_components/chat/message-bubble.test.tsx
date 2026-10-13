import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  LIGHTHOUSE_V2_MESSAGE_ROLE,
  LIGHTHOUSE_V2_PART_TYPE,
  type LighthouseV2Message,
} from "@/app/(prowler)/lighthouse/_types";

import {
  LIGHTHOUSE_FEEDBACK_DETAILS_MAX_LENGTH,
  type LighthouseFeedbackSurvey,
} from "./lighthouse-feedback-survey";
import { MessageBubble } from "./message-bubble";

const { captureMock } = vi.hoisted(() => ({
  captureMock: vi.fn(),
}));

vi.mock("posthog-js", () => ({
  default: { capture: captureMock },
}));

const FEEDBACK_SURVEY = {
  id: "survey-123",
  name: "Lighthouse Request Outcome Feedback",
  ratingQuestion: {
    id: "rating-question-id",
    question: "How was this outcome?",
  },
  reasonsQuestion: {
    id: "reasons-question-id",
    question: "What could be improved?",
  },
  detailsQuestion: {
    id: "details-question-id",
    question: "Additional feedback",
  },
} satisfies LighthouseFeedbackSurvey;

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
  beforeEach(() => {
    captureMock.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

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

  it("should render a skill launch as a card instead of the raw prompt", () => {
    // Given
    const skillMessage: LighthouseV2Message = {
      id: "message-user-skill",
      role: LIGHTHOUSE_V2_MESSAGE_ROLE.USER,
      model: null,
      tokenUsage: null,
      insertedAt: "2026-06-25T10:00:00Z",
      parts: [
        {
          id: "part-user-skill",
          type: LIGHTHOUSE_V2_PART_TYPE.TEXT,
          content: {
            text: "[PROWLER_UI_SKILL_V1]\ninstructions\n[/PROWLER_UI_SKILL_V1]\n\nTriage Decision",
            display_text: "Triage Decision",
            ui_skill: {
              skill_id: "triage-decision",
              name: "Triage Decision",
              version: 1,
            },
            ui_context: {
              schema_version: 1,
              transport: "inline",
              items: [
                {
                  kind: "finding",
                  id: "finding-1",
                  source: "focused",
                  scope_key: "findings:/findings",
                  label:
                    "Inline IAM policy does not allow '*:*' administrative privileges",
                  finding_id: "finding-1",
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
    render(<MessageBubble message={skillMessage} />);

    // Then
    expect(screen.getByText("Skill")).toBeInTheDocument();
    expect(screen.getByText("Triage Decision")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Inline IAM policy does not allow '*:*' administrative privileges",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/PROWLER_UI_SKILL_V1/)).not.toBeInTheDocument();
  });

  it("should render a skill response with receipt and follow-up actions", async () => {
    // Given
    const user = userEvent.setup();
    const assistantMessage: LighthouseV2Message = {
      id: "message-assistant-skill",
      role: LIGHTHOUSE_V2_MESSAGE_ROLE.ASSISTANT,
      model: null,
      tokenUsage: null,
      insertedAt: "2026-06-25T10:00:42Z",
      parts: [
        {
          id: "part-tool-1",
          type: LIGHTHOUSE_V2_PART_TYPE.TOOL_CALL,
          content: {
            tool_call_id: "tool-1",
            tool_name: "get_finding",
            arguments: {},
            result: "ok",
          },
          toolCallOutcome: "success",
          insertedAt: "2026-06-25T10:00:10Z",
          updatedAt: "2026-06-25T10:00:12Z",
        },
        {
          id: "part-answer",
          type: LIGHTHOUSE_V2_PART_TYPE.TEXT,
          content: {
            text: "The finding is exploitable in practice.",
          },
          toolCallOutcome: null,
          insertedAt: "2026-06-25T10:00:40Z",
          updatedAt: "2026-06-25T10:00:40Z",
        },
      ],
    };
    const onLaunchSkill = vi.fn();

    // When
    render(
      <MessageBubble
        message={assistantMessage}
        skillRun={{
          ref: {
            skillId: "triage-decision",
            name: "Triage Decision",
            version: 1,
          },
          launchedAt: "2026-06-25T10:00:00Z",
          context: {
            schemaVersion: 1,
            transport: "inline",
            items: [
              {
                kind: "finding",
                id: "finding-1",
                source: "focused",
                scopeKey: "findings:/findings",
                label: "Inline IAM policy finding",
                findingId: "finding-1",
              },
            ],
          },
        }}
        onLaunchSkill={onLaunchSkill}
      />,
    );

    // Then: receipt with tools and duration — no plan-derived step count
    expect(screen.getByText(/1 tool · 42s/)).toBeInTheDocument();
    expect(
      screen.getByText("The finding is exploitable in practice."),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Create Jira ticket" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Mute finding" }),
    ).toBeInTheDocument();

    // And the suggested next skill launches through the callback
    await user.click(
      screen.getByRole("button", { name: /Next: Contextual Fix/ }),
    );
    expect(onLaunchSkill).toHaveBeenCalledOnce();
    expect(onLaunchSkill.mock.calls[0][0]).toMatchObject({
      id: "contextual-fix",
    });
  });

  it("should render the receipt as a static line with the tool trace inline", () => {
    // Given: a finished skill run whose narration interleaves with a tool call
    const assistantMessage = buildAssistantMessage([
      textPart("part-narration", "Checking the failed policy."),
      toolCallPart("part-tool-1", "get_finding"),
      textPart("part-answer", "Done."),
    ]);

    render(
      <MessageBubble
        message={assistantMessage}
        skillRun={{
          ref: {
            skillId: "triage-decision",
            name: "Triage Decision",
            version: 1,
          },
          launchedAt: "2026-06-25T10:00:00Z",
        }}
      />,
    );

    // Then: the receipt is informational only — it owns no disclosure…
    expect(screen.getByText(/1 tool/)).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Ran/ }),
    ).not.toBeInTheDocument();

    // …and the tool call renders in message order between the narration and
    // the answer, behind the body's own group.
    expect(screen.getByText("Checking the failed policy.")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Used Get finding/ }),
    ).toBeInTheDocument();
    expect(screen.getByText("Done.")).toBeInTheDocument();
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

  describe("when rendering feedback controls", () => {
    it("should show controls for an assistant answer with a persisted user feedback target", () => {
      // Given / When
      renderFeedbackBubble();

      // Then
      expect(
        screen.getByRole("button", { name: "Mark outcome as helpful" }),
      ).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: "Mark outcome as not helpful" }),
      ).toBeInTheDocument();
    });

    it("should not show controls under a user prompt", () => {
      // Given
      const message = buildUserMessage();

      // When
      render(<MessageBubble message={message} />);

      // Then
      expect(
        screen.queryByRole("button", { name: "Mark outcome as helpful" }),
      ).not.toBeInTheDocument();
    });

    it("should not show controls for an assistant without a feedback target", () => {
      // Given
      const message = buildAssistantMessage([textPart("part-1", "Done")]);

      // When
      render(<MessageBubble message={message} />);

      // Then
      expect(
        screen.queryByRole("button", { name: "Mark outcome as helpful" }),
      ).not.toBeInTheDocument();
    });

    it("should not show controls for an optimistic user feedback target", () => {
      // Given
      const message = buildAssistantMessage([textPart("part-1", "Done")]);

      // When
      render(
        <MessageBubble
          message={message}
          feedbackTarget={buildUserMessage("optimistic-user-1")}
          feedbackSurvey={FEEDBACK_SURVEY}
        />,
      );

      // Then
      expect(
        screen.queryByRole("button", { name: "Mark outcome as helpful" }),
      ).not.toBeInTheDocument();
    });
  });

  describe("when rating an assistant answer", () => {
    it("should submit thumbs up immediately without opening the feedback form", async () => {
      // Given
      const user = userEvent.setup();
      renderFeedbackBubble();

      // When
      await user.click(
        screen.getByRole("button", { name: "Mark outcome as helpful" }),
      );

      // Then
      expect(captureMock).toHaveBeenCalledWith(
        "survey sent",
        expect.objectContaining({
          $ai_trace_id: "message-user-1",
          $survey_id: "survey-123",
          $survey_name: "Lighthouse Request Outcome Feedback",
          "$survey_response_rating-question-id": 1,
          $survey_completed: true,
        }),
      );
      expect(
        screen.queryByRole("heading", { name: "Share feedback" }),
      ).not.toBeInTheDocument();
    });

    it("should keep controls usable and assign a fresh submission identifier for each capture", async () => {
      // Given
      const user = userEvent.setup();
      vi.spyOn(globalThis.crypto, "randomUUID")
        .mockReturnValueOnce("submission-1")
        .mockReturnValueOnce("submission-2");
      renderFeedbackBubble();
      const helpfulButton = screen.getByRole("button", {
        name: "Mark outcome as helpful",
      });

      // When
      await user.click(helpfulButton);

      // Then
      expect(helpfulButton).toBeEnabled();
      expect(captureMock).toHaveBeenNthCalledWith(
        1,
        "survey sent",
        expect.objectContaining({
          $survey_submission_id: "submission-1",
        }),
      );

      // When
      await user.click(helpfulButton);

      // Then
      expect(captureMock).toHaveBeenNthCalledWith(
        2,
        "survey sent",
        expect.objectContaining({
          $survey_submission_id: "submission-2",
        }),
      );
    });

    it("should open the feedback form with the chosen rating without submitting", async () => {
      // Given
      const user = userEvent.setup();
      renderFeedbackBubble();

      // When
      await user.click(
        screen.getByRole("button", { name: "Mark outcome as not helpful" }),
      );

      // Then
      expect(
        screen.getByRole("heading", { name: "Share feedback" }),
      ).toBeVisible();
      expect(
        screen.getByRole("button", { name: "Mark outcome as not helpful" }),
      ).toHaveAttribute("aria-pressed", "true");
      expect(
        screen.getByLabelText("Additional feedback (optional)"),
      ).toHaveAttribute(
        "maxlength",
        String(LIGHTHOUSE_FEEDBACK_DETAILS_MAX_LENGTH),
      );
      expect(captureMock).not.toHaveBeenCalled();
    });

    it("should submit selected feedback reasons with trimmed optional details", async () => {
      // Given
      const user = userEvent.setup();
      renderFeedbackBubble();

      // When
      await user.click(
        screen.getByRole("button", { name: "Mark outcome as not helpful" }),
      );
      const styleReason = screen.getByRole("button", {
        name: "Don't like the style",
      });
      expect(
        within(screen.getByRole("group", { name: "Reasons (optional)" }))
          .getAllByRole("button")
          .map((button) => button.textContent),
      ).toEqual([
        "Don't like the style",
        "Didn't fully follow instructions",
        "Low quality",
        "Biased",
        "Safety or legal concern",
        "Other",
      ]);
      styleReason.focus();
      await user.keyboard("{Enter}");
      await user.click(screen.getByRole("button", { name: "Low quality" }));

      // Then - keyboard and pointer interactions retain a multi-select pressed state.
      expect(styleReason).toHaveAttribute("aria-pressed", "true");
      expect(
        screen.getByRole("button", { name: "Low quality" }),
      ).toHaveAttribute("aria-pressed", "true");

      // When
      await user.type(
        screen.getByLabelText("Additional feedback (optional)"),
        "  Missing evidence  ",
      );
      await user.click(screen.getByRole("button", { name: "Submit" }));

      // Then
      expect(captureMock).toHaveBeenCalledTimes(3);
      expect(captureMock).toHaveBeenLastCalledWith(
        "survey sent",
        expect.objectContaining({
          $ai_trace_id: "message-user-1",
          "$survey_response_rating-question-id": 2,
          "$survey_response_reasons-question-id": [
            "Don't like the style",
            "Low quality",
          ],
          "$survey_response_details-question-id": "Missing evidence",
          $survey_completed: true,
        }),
      );
    });

    it("should submit thumbs down without optional reasons or details", async () => {
      // Given
      const user = userEvent.setup();
      renderFeedbackBubble();

      // When
      await user.click(
        screen.getByRole("button", { name: "Mark outcome as not helpful" }),
      );
      await user.click(screen.getByRole("button", { name: "Submit" }));

      // Then
      expect(captureMock).toHaveBeenCalledWith(
        "survey sent",
        expect.objectContaining({
          $ai_trace_id: "message-user-1",
          "$survey_response_rating-question-id": 2,
          $survey_completed: true,
        }),
      );
    });

    it("should cancel without submitting and clear the draft", async () => {
      // Given
      const user = userEvent.setup();
      renderFeedbackBubble();
      await user.click(
        screen.getByRole("button", { name: "Mark outcome as not helpful" }),
      );
      await user.click(
        screen.getByRole("button", { name: "Don't like the style" }),
      );
      await user.type(
        screen.getByLabelText("Additional feedback (optional)"),
        "Unsaved draft",
      );

      // When
      await user.click(screen.getByRole("button", { name: "Cancel" }));

      // Then
      expect(captureMock).not.toHaveBeenCalled();
      expect(
        screen.queryByRole("heading", { name: "Share feedback" }),
      ).not.toBeInTheDocument();
      await user.click(
        screen.getByRole("button", { name: "Mark outcome as not helpful" }),
      );
      expect(
        screen.getByLabelText("Additional feedback (optional)"),
      ).toHaveValue("");
      expect(
        screen.getByRole("button", { name: "Don't like the style" }),
      ).toHaveAttribute("aria-pressed", "false");
    });

    it("should clear selected feedback reasons after a successful submission", async () => {
      // Given
      const user = userEvent.setup();
      renderFeedbackBubble();
      await user.click(
        screen.getByRole("button", { name: "Mark outcome as not helpful" }),
      );
      await user.click(
        screen.getByRole("button", { name: "Don't like the style" }),
      );

      // When
      await user.click(screen.getByRole("button", { name: "Submit" }));
      expect(
        screen.queryByRole("heading", { name: "Share feedback" }),
      ).not.toBeInTheDocument();
      await user.click(
        screen.getByRole("button", { name: "Mark outcome as not helpful" }),
      );

      // Then
      expect(
        screen.getByRole("button", { name: "Don't like the style" }),
      ).toHaveAttribute("aria-pressed", "false");
    });

    it("should close the feedback popup without submitting", async () => {
      // Given
      const user = userEvent.setup();
      renderFeedbackBubble();
      await user.click(
        screen.getByRole("button", { name: "Mark outcome as not helpful" }),
      );

      // When
      await user.keyboard("{Escape}");

      // Then
      expect(captureMock).not.toHaveBeenCalled();
      expect(
        screen.queryByRole("heading", { name: "Share feedback" }),
      ).not.toBeInTheDocument();
    });

    it("should discard the feedback draft when the popup closes with Escape", async () => {
      // Given
      const user = userEvent.setup();
      renderFeedbackBubble();
      await user.click(
        screen.getByRole("button", { name: "Mark outcome as not helpful" }),
      );
      await user.click(
        screen.getByRole("button", { name: "Don't like the style" }),
      );
      await user.type(
        screen.getByLabelText("Additional feedback (optional)"),
        "Unsaved draft",
      );

      // When
      await user.keyboard("{Escape}");
      await user.click(
        screen.getByRole("button", { name: "Mark outcome as not helpful" }),
      );

      // Then
      expect(
        screen.getByLabelText("Additional feedback (optional)"),
      ).toHaveValue("");
      expect(
        screen.getByRole("button", { name: "Don't like the style" }),
      ).toHaveAttribute("aria-pressed", "false");
    });
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

function buildUserMessage(id = "message-user-1"): LighthouseV2Message {
  return {
    id,
    role: LIGHTHOUSE_V2_MESSAGE_ROLE.USER,
    model: null,
    tokenUsage: null,
    insertedAt: "2026-06-25T10:00:00Z",
    parts: [textPart("part-user-1", "Run this check")],
  };
}

function renderFeedbackBubble() {
  return render(
    <MessageBubble
      message={buildAssistantMessage([textPart("part-1", "Done")])}
      feedbackTarget={buildUserMessage()}
      feedbackSurvey={FEEDBACK_SURVEY}
    />,
  );
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
