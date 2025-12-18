/**
 * MessageItem component
 * Renders individual chat messages with actions for assistant messages
 */

import { Copy, RotateCcw } from "lucide-react";
import { defaultRehypePlugins, Streamdown } from "streamdown";

import { Action, Actions } from "@/components/lighthouse/ai-elements/actions";
import { ChainOfThoughtDisplay } from "@/components/lighthouse/chain-of-thought-display";
import {
  extractChainOfThoughtEvents,
  extractMessageText,
  type Message,
  MESSAGE_ROLES,
  MESSAGE_STATUS,
} from "@/components/lighthouse/chat-utils";
import { Loader } from "@/components/lighthouse/loader";

/**
 * Escapes angle-bracket placeholders like <bucket_name> to HTML entities
 * so they display correctly instead of being interpreted as HTML tags.
 *
 * This processes the text while preserving:
 * - Content inside inline code (backticks)
 * - Content inside code blocks (triple backticks)
 */
function escapeAngleBracketPlaceholders(text: string): string {
  // HTML tags to preserve (not escape)
  const htmlTags = new Set([
    "div",
    "span",
    "p",
    "a",
    "img",
    "br",
    "hr",
    "ul",
    "ol",
    "li",
    "table",
    "tr",
    "td",
    "th",
    "thead",
    "tbody",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "pre",
    "blockquote",
    "strong",
    "em",
    "b",
    "i",
    "u",
    "s",
    "sub",
    "sup",
    "details",
    "summary",
  ]);

  // Split by code blocks and inline code to preserve them
  // This regex captures: ```...``` blocks, `...` inline code, and everything else
  const parts = text.split(/(```[\s\S]*?```|`[^`]+`)/g);

  return parts
    .map((part) => {
      // If it's a code block or inline code, leave it untouched
      // Shiki/syntax highlighter handles escaping inside code blocks
      if (part.startsWith("```") || part.startsWith("`")) {
        return part;
      }

      // For regular text outside code, wrap placeholders in backticks
      return part.replace(/<([a-zA-Z][a-zA-Z0-9_-]*)>/g, (match, tagName) => {
        if (htmlTags.has(tagName.toLowerCase())) {
          return match;
        }
        return `\`<${tagName}>\``;
      });
    })
    .join("");
}

interface MessageItemProps {
  message: Message;
  index: number;
  isLastMessage: boolean;
  status: string;
  onCopy: (text: string) => void;
  onRegenerate: () => void;
}

export function MessageItem({
  message,
  index,
  isLastMessage,
  status,
  onCopy,
  onRegenerate,
}: MessageItemProps) {
  const messageText = extractMessageText(message);

  // Check if this is the streaming assistant message
  const isStreamingAssistant =
    isLastMessage &&
    message.role === MESSAGE_ROLES.ASSISTANT &&
    status === MESSAGE_STATUS.STREAMING;

  // Use a composite key to ensure uniqueness even if IDs are duplicated temporarily
  const uniqueKey = `${message.id}-${index}-${message.role}`;

  // Extract chain-of-thought events from message parts
  const chainOfThoughtEvents = extractChainOfThoughtEvents(message);

  return (
    <div key={uniqueKey}>
      <div
        className={`flex ${
          message.role === MESSAGE_ROLES.USER ? "justify-end" : "justify-start"
        }`}
      >
        <div
          className={`max-w-[80%] rounded-lg px-4 py-2 ${
            message.role === MESSAGE_ROLES.USER
              ? "bg-bg-neutral-tertiary border-border-neutral-secondary border"
              : "bg-muted"
          }`}
        >
          {/* Chain of Thought for assistant messages */}
          {message.role === MESSAGE_ROLES.ASSISTANT && (
            <ChainOfThoughtDisplay
              events={chainOfThoughtEvents}
              isStreaming={isStreamingAssistant}
              messageKey={uniqueKey}
            />
          )}

          {/* Show loader only if streaming with no text AND no chain-of-thought events */}
          {isStreamingAssistant &&
          !messageText &&
          chainOfThoughtEvents.length === 0 ? (
            <Loader size="default" text="Thinking..." />
          ) : messageText ? (
            <div>
              {message.role === MESSAGE_ROLES.USER ? (
                // User messages: render as plain text to preserve HTML-like tags
                <p className="text-sm whitespace-pre-wrap">{messageText}</p>
              ) : (
                // Assistant messages: render with markdown support
                <div className="lighthouse-markdown">
                  <Streamdown
                    parseIncompleteMarkdown={true}
                    shikiTheme={["github-light", "github-dark"]}
                    controls={{
                      code: true,
                      table: true,
                      mermaid: true,
                    }}
                    rehypePlugins={[
                      // Omit defaultRehypePlugins.raw to escape HTML tags like <code>, <bucket_name>, etc.
                      // This prevents them from being interpreted as HTML elements
                      defaultRehypePlugins.katex,
                      defaultRehypePlugins.harden,
                    ]}
                    isAnimating={isStreamingAssistant}
                  >
                    {escapeAngleBracketPlaceholders(messageText)}
                  </Streamdown>
                </div>
              )}
            </div>
          ) : null}
        </div>
      </div>

      {/* Actions for assistant messages */}
      {message.role === MESSAGE_ROLES.ASSISTANT &&
        isLastMessage &&
        messageText &&
        status !== MESSAGE_STATUS.STREAMING && (
          <div className="mt-2 flex justify-start">
            <Actions className="max-w-[80%]">
              <Action
                tooltip="Copy message"
                label="Copy"
                onClick={() => onCopy(messageText)}
              >
                <Copy className="h-3 w-3" />
              </Action>
              <Action
                tooltip="Regenerate response"
                label="Retry"
                onClick={onRegenerate}
              >
                <RotateCcw className="h-3 w-3" />
              </Action>
            </Actions>
          </div>
        )}
    </div>
  );
}
