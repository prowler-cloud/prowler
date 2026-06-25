"use client";

import { Bot, Check, Copy, UserRound, Wrench } from "lucide-react";
import { useState } from "react";

import { formatMessageTimestamp } from "@/app/(prowler)/lighthouse/_lib/format";
import { getTextContent } from "@/app/(prowler)/lighthouse/_lib/messages";
import {
  LIGHTHOUSE_V2_MESSAGE_ROLE,
  LIGHTHOUSE_V2_PART_TYPE,
  type LighthouseV2Message,
} from "@/app/(prowler)/lighthouse/_types";
import { Button } from "@/components/shadcn/button/button";
import { cn } from "@/lib/utils";

import { MessageMarkdown } from "./message-markdown";

export function MessageBubble({ message }: { message: LighthouseV2Message }) {
  const isUser = message.role === LIGHTHOUSE_V2_MESSAGE_ROLE.USER;
  const textParts = message.parts.filter(
    (part) => part.type === LIGHTHOUSE_V2_PART_TYPE.TEXT,
  );
  const toolCallCount = message.parts.filter(
    (part) => part.type === LIGHTHOUSE_V2_PART_TYPE.TOOL_CALL,
  ).length;
  const messageText = textParts
    .map((part) => getTextContent(part.content))
    .filter(Boolean)
    .join("\n\n");

  return (
    <article
      className={cn(
        "group flex gap-3",
        isUser ? "justify-end" : "justify-start",
      )}
    >
      {!isUser && <Bot className="text-text-neutral-tertiary mt-1 size-5" />}
      <div
        className={cn(
          "flex max-w-[min(760px,85%)] flex-col gap-1",
          isUser ? "items-end" : "items-start",
        )}
      >
        <div
          className={cn(
            "rounded-[8px] px-4 py-3 text-sm",
            isUser
              ? "bg-button-primary text-black"
              : "bg-bg-neutral-tertiary text-text-neutral-primary",
          )}
        >
          {toolCallCount > 0 && (
            <p className="text-text-neutral-secondary mb-2 flex items-center gap-1.5 text-xs">
              <Wrench className="size-3.5" />
              {toolCallCount} {toolCallCount === 1 ? "tool" : "tools"} called
            </p>
          )}
          {/* User text stays plain to preserve HTML-like tags; assistant text
              renders as markdown. */}
          {isUser ? (
            <p className="whitespace-pre-wrap">{messageText}</p>
          ) : (
            <MessageMarkdown text={messageText} />
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
