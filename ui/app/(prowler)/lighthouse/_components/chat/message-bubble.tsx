"use client";

import {
  Bot,
  Check,
  Copy,
  ThumbsDown,
  ThumbsUp,
  UserRound,
} from "lucide-react";
import { useState } from "react";

import { updateLighthouseV2MessageFeedback } from "@/app/(prowler)/lighthouse/_actions";
import { formatMessageTimestamp } from "@/app/(prowler)/lighthouse/_lib/format";
import {
  getLighthouseContext,
  getSkillRef,
  getTextContent,
  type SkillRunInfo,
} from "@/app/(prowler)/lighthouse/_lib/messages";
import {
  LIGHTHOUSE_V2_FEEDBACK_RATING,
  LIGHTHOUSE_V2_MESSAGE_ROLE,
  LIGHTHOUSE_V2_PART_TYPE,
  type LighthouseV2FeedbackRating,
  type LighthouseV2Message,
  type LighthouseV2Part,
} from "@/app/(prowler)/lighthouse/_types";
import { LighthouseContextBadge } from "@/components/lighthouse/context-chip";
import { Button } from "@/components/shadcn/button/button";
import { cn } from "@/lib/utils";
import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

import { MessageMarkdown } from "./message-markdown";
import { SkillActionsRow, SkillRunReceipt } from "./skill-completed";
import { SkillMessageCard } from "./skill-message-card";
import { ToolCalls } from "./tool-call-part";

const ASSISTANT_PART_GROUP_TYPE = {
  TEXT: "text",
  TOOL_CALL: "tool_call",
} as const;

type AssistantPartGroupType =
  (typeof ASSISTANT_PART_GROUP_TYPE)[keyof typeof ASSISTANT_PART_GROUP_TYPE];

interface AssistantPartGroup {
  id: string;
  type: AssistantPartGroupType;
  parts: LighthouseV2Part[];
}

interface MessageBubbleProps {
  message: LighthouseV2Message;
  sessionId?: string;
  // Present when this assistant message answered a skill launch (design 1j).
  skillRun?: SkillRunInfo;
  onLaunchSkill?: (skill: LighthouseSkillDefinition) => void;
}

export function MessageBubble({
  message,
  sessionId,
  skillRun,
  onLaunchSkill,
}: MessageBubbleProps) {
  const isUser = message.role === LIGHTHOUSE_V2_MESSAGE_ROLE.USER;
  const isSkillResponse = !isUser && skillRun !== undefined;
  // Text-only join feeds the copy button; tool calls are rendered separately.
  const messageText = message.parts
    .filter((part) => part.type === LIGHTHOUSE_V2_PART_TYPE.TEXT)
    .map((part) => getTextContent(part.content))
    .filter(Boolean)
    .join("\n\n");
  const messageContext = isUser
    ? message.parts
        .filter((part) => part.type === LIGHTHOUSE_V2_PART_TYPE.TEXT)
        .map((part) => getLighthouseContext(part.content))
        .find((context) => context !== undefined)
    : undefined;
  // A user turn that launched a skill renders as a card, not as prompt text.
  const messageSkill = isUser
    ? message.parts
        .filter((part) => part.type === LIGHTHOUSE_V2_PART_TYPE.TEXT)
        .map((part) => getSkillRef(part.content))
        .find((skillRef) => skillRef !== undefined)
    : undefined;

  return (
    <article
      className={cn(
        "group flex min-w-0 gap-3",
        isUser ? "justify-end" : "justify-start",
      )}
    >
      {!isUser && <Bot className="text-text-neutral-tertiary mt-1 size-5" />}
      <div
        className={cn(
          "flex max-w-[min(760px,85%)] min-w-0 flex-col gap-1",
          isUser ? "items-end" : "items-start",
        )}
      >
        {messageContext && <LighthouseContextBadge context={messageContext} />}
        {isSkillResponse && (
          <SkillRunReceipt
            skillRun={skillRun}
            parts={message.parts}
            completedAt={message.insertedAt}
          />
        )}
        {messageSkill ? (
          <SkillMessageCard skillRef={messageSkill} context={messageContext} />
        ) : (
          <div
            className={cn(
              "max-w-full min-w-0 rounded-[8px] px-4 py-3 text-sm",
              isUser
                ? "bg-button-primary text-slate-950"
                : "bg-bg-neutral-tertiary text-text-neutral-primary",
            )}
          >
            {/* User text stays plain to preserve HTML-like tags; assistant
                renders parts in order so tool calls sit between the narration
                text that announced them — skill responses included, with the
                receipt above as the run summary. */}
            {isUser ? (
              <p className="wrap-break-word whitespace-pre-wrap">
                {messageText}
              </p>
            ) : (
              <AssistantParts parts={message.parts} />
            )}
          </div>
        )}
        {isSkillResponse && (
          <SkillActionsRow skillRun={skillRun} onLaunchSkill={onLaunchSkill} />
        )}
        <MessageMeta
          isUser={isUser}
          text={messageText}
          insertedAt={message.insertedAt}
          message={message}
          sessionId={sessionId}
        />
      </div>
      {isUser && (
        <UserRound className="text-text-neutral-tertiary mt-1 size-5" />
      )}
    </article>
  );
}

function AssistantParts({ parts }: { parts: LighthouseV2Part[] }) {
  const groups = groupAssistantParts(parts);

  return (
    <div className="min-w-0 space-y-3">
      {groups.map((group) =>
        group.type === ASSISTANT_PART_GROUP_TYPE.TOOL_CALL ? (
          <ToolCalls key={group.id} parts={group.parts} />
        ) : (
          <AssistantTextParts key={group.id} parts={group.parts} />
        ),
      )}
    </div>
  );
}

function AssistantTextParts({ parts }: { parts: LighthouseV2Part[] }) {
  return parts.map((part, index) => {
    const text = getTextContent(part.content);
    return text ? (
      <MessageMarkdown key={part.id || `text-${index}`} text={text} />
    ) : null;
  });
}

function groupAssistantParts(parts: LighthouseV2Part[]): AssistantPartGroup[] {
  return parts.reduce<AssistantPartGroup[]>((groups, part, index) => {
    const groupType = getAssistantPartGroupType(part);
    if (!groupType) {
      return groups;
    }

    const lastGroup = groups.at(-1);
    if (lastGroup?.type === groupType) {
      return [
        ...groups.slice(0, -1),
        {
          ...lastGroup,
          parts: [...lastGroup.parts, part],
        },
      ];
    }

    return [
      ...groups,
      {
        id: `${groupType}-${part.id || index}`,
        type: groupType,
        parts: [part],
      },
    ];
  }, []);
}

function getAssistantPartGroupType(
  part: LighthouseV2Part,
): AssistantPartGroupType | null {
  if (part.type === LIGHTHOUSE_V2_PART_TYPE.TEXT) {
    return ASSISTANT_PART_GROUP_TYPE.TEXT;
  }
  if (part.type === LIGHTHOUSE_V2_PART_TYPE.TOOL_CALL) {
    return ASSISTANT_PART_GROUP_TYPE.TOOL_CALL;
  }
  return null;
}

function MessageMeta({
  isUser,
  text,
  insertedAt,
  message,
  sessionId,
}: {
  isUser: boolean;
  text: string;
  insertedAt: string;
  message: LighthouseV2Message;
  sessionId?: string;
}) {
  // Copy is always shown; the timestamp only reveals on hover over the message.
  // Agent footer reads left-to-right ([copy] [time]); user footer mirrors it.
  return (
    <div
      className={cn(
        "flex items-center gap-1 px-1",
        isUser && "flex-row-reverse",
      )}
    >
      <CopyMessageButton text={text} />
      <MessageFeedbackControls
        key={`${message.id}:${message.feedback ?? ""}`}
        message={message}
        sessionId={sessionId}
      />
      <time
        dateTime={insertedAt}
        className="text-text-neutral-tertiary text-xs opacity-0 transition-opacity group-hover:opacity-100"
      >
        {formatMessageTimestamp(insertedAt)}
      </time>
    </div>
  );
}

function MessageFeedbackControls({
  message,
  sessionId,
}: {
  message: LighthouseV2Message;
  sessionId?: string;
}) {
  const [feedbackOverride, setFeedbackOverride] = useState<{
    rating: LighthouseV2FeedbackRating | null;
    isPending: boolean;
  } | null>(null);
  const rating = feedbackOverride
    ? feedbackOverride.rating
    : (message.feedback ?? null);
  const isSubmitting = feedbackOverride?.isPending ?? false;
  const isPersistedUserMessage =
    message.role === LIGHTHOUSE_V2_MESSAGE_ROLE.USER &&
    message.feedback !== undefined;

  if (!sessionId || !isPersistedUserMessage) return null;

  const submitRating = async (nextRating: LighthouseV2FeedbackRating) => {
    if (isSubmitting || rating === nextRating) return;
    setFeedbackOverride({ rating: nextRating, isPending: true });
    try {
      const result = await updateLighthouseV2MessageFeedback({
        sessionId,
        messageId: message.id,
        feedback: nextRating,
      });
      if ("error" in result) {
        setFeedbackOverride(null);
      } else {
        setFeedbackOverride({
          rating: result.data.feedback ?? null,
          isPending: false,
        });
      }
    } catch {
      setFeedbackOverride(null);
    }
  };

  return (
    <div className="flex items-center gap-0.5">
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        aria-label="Mark outcome as helpful"
        aria-pressed={rating === LIGHTHOUSE_V2_FEEDBACK_RATING.UP}
        disabled={isSubmitting}
        onClick={() => void submitRating(LIGHTHOUSE_V2_FEEDBACK_RATING.UP)}
        className={cn(
          "text-text-neutral-tertiary hover:text-text-neutral-primary size-6",
          rating === LIGHTHOUSE_V2_FEEDBACK_RATING.UP &&
            "bg-button-primary hover:bg-button-primary-hover active:bg-button-primary-press focus-visible:ring-button-primary/50 text-black hover:text-black",
        )}
      >
        <ThumbsUp className="size-3.5" />
      </Button>
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        aria-label="Mark outcome as not helpful"
        aria-pressed={rating === LIGHTHOUSE_V2_FEEDBACK_RATING.DOWN}
        disabled={isSubmitting}
        onClick={() => void submitRating(LIGHTHOUSE_V2_FEEDBACK_RATING.DOWN)}
        className={cn(
          "text-text-neutral-tertiary hover:text-text-neutral-primary size-6",
          rating === LIGHTHOUSE_V2_FEEDBACK_RATING.DOWN &&
            "bg-button-primary hover:bg-button-primary-hover active:bg-button-primary-press focus-visible:ring-button-primary/50 text-black hover:text-black",
        )}
      >
        <ThumbsDown className="size-3.5" />
      </Button>
    </div>
  );
}

function CopyMessageButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard can reject (e.g. permissions); nothing to recover.
    }
  };

  return (
    <Button
      type="button"
      variant="ghost"
      size="icon-sm"
      aria-label="Copy message"
      onClick={handleCopy}
      className="text-text-neutral-tertiary hover:text-text-neutral-primary size-6"
    >
      {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
    </Button>
  );
}
