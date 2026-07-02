"use client";

import { Bot, Check, Copy, UserRound } from "lucide-react";
import { useState } from "react";

import { formatMessageTimestamp } from "@/app/(prowler)/lighthouse/_lib/format";
import { getTextContent } from "@/app/(prowler)/lighthouse/_lib/messages";
import {
  LIGHTHOUSE_V2_MESSAGE_ROLE,
  LIGHTHOUSE_V2_PART_TYPE,
  type LighthouseV2Message,
  type LighthouseV2Part,
} from "@/app/(prowler)/lighthouse/_types";
import { Button } from "@/components/shadcn/button/button";
import { cn } from "@/lib/utils";

import { MessageMarkdown } from "./message-markdown";
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

export function MessageBubble({ message }: { message: LighthouseV2Message }) {
  const isUser = message.role === LIGHTHOUSE_V2_MESSAGE_ROLE.USER;
  // Text-only join feeds the copy button; tool calls are rendered separately.
  const messageText = message.parts
    .filter((part) => part.type === LIGHTHOUSE_V2_PART_TYPE.TEXT)
    .map((part) => getTextContent(part.content))
    .filter(Boolean)
    .join("\n\n");

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
        <div
          className={cn(
            "max-w-full min-w-0 rounded-[8px] px-4 py-3 text-sm",
            isUser
              ? "bg-button-primary text-slate-950"
              : "bg-bg-neutral-tertiary text-text-neutral-primary",
          )}
        >
          {/* User text stays plain to preserve HTML-like tags; assistant
              renders parts in order so tool calls sit between text blocks. */}
          {isUser ? (
            <p className="whitespace-pre-wrap">{messageText}</p>
          ) : (
            <AssistantParts parts={message.parts} />
          )}
        </div>
        <MessageMeta
          isUser={isUser}
          text={messageText}
          insertedAt={message.insertedAt}
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
}: {
  isUser: boolean;
  text: string;
  insertedAt: string;
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
      <time
        dateTime={insertedAt}
        className="text-text-neutral-tertiary text-xs opacity-0 transition-opacity group-hover:opacity-100"
      >
        {formatMessageTimestamp(insertedAt)}
      </time>
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
