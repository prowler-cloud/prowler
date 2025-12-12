/**
 * MessageItem component
 * Renders individual chat messages with actions for assistant messages
 */

import { Copy, RotateCcw } from "lucide-react";
import { Streamdown } from "streamdown";

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
              <Streamdown
                parseIncompleteMarkdown={true}
                shikiTheme={["github-light", "github-dark"]}
                controls={{
                  code: true,
                  table: true,
                  mermaid: true,
                }}
                isAnimating={isStreamingAssistant}
              >
                {messageText}
              </Streamdown>
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
