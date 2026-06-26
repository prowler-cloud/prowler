"use client";

import { CornerDownLeft, Settings } from "lucide-react";
import Link from "next/link";
import { type FormEvent } from "react";

import { Button } from "@/components/shadcn/button/button";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { Textarea } from "@/components/shadcn/textarea/textarea";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";

interface ChatComposerPanelProps {
  feedback: string | null;
  canRetry: boolean;
  onRetry: () => void;
  canSend: boolean;
  input: string;
  isStreaming: boolean;
  selectedConfigurationConnected: boolean;
  onInputChange: (value: string) => void;
  onStop: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onSubmitText: (text: string) => Promise<void>;
}

// Feedback banner + input, shared by the empty and active chat layouts so the
// two branches can't drift apart.
export function ChatComposerPanel({
  feedback,
  canRetry,
  onRetry,
  ...composerProps
}: ChatComposerPanelProps) {
  return (
    <>
      <ChatFeedbackBar
        feedback={feedback}
        canRetry={canRetry}
        onRetry={onRetry}
      />
      <ChatComposer {...composerProps} />
    </>
  );
}

function ChatFeedbackBar({
  feedback,
  canRetry,
  onRetry,
}: {
  feedback: string | null;
  canRetry: boolean;
  onRetry: () => void;
}) {
  if (!feedback) return null;

  return (
    <div className="border-border-neutral-secondary bg-bg-neutral-secondary mb-3 flex items-center justify-between gap-3 rounded-[8px] border px-3 py-2 text-sm">
      <span>{feedback}</span>
      {canRetry && (
        <Button type="button" variant="outline" size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

interface ChatComposerProps {
  canSend: boolean;
  input: string;
  isStreaming: boolean;
  selectedConfigurationConnected: boolean;
  onInputChange: (value: string) => void;
  // Kept on the contract but unused for now: the backend can't cancel a run yet,
  // so the stop control is replaced by a non-interactive spinner.
  onStop: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onSubmitText: (text: string) => Promise<void>;
}

function ChatComposer({
  canSend,
  input,
  isStreaming,
  selectedConfigurationConnected,
  onInputChange,
  onSubmit,
  onSubmitText,
}: ChatComposerProps) {
  return (
    <form
      className="border-border-neutral-secondary bg-bg-neutral-tertiary has-[textarea:focus]:border-border-input-primary-press flex min-h-[150px] w-full flex-col overflow-hidden rounded-[8px] border shadow-xs transition-all"
      onSubmit={onSubmit}
    >
      <Textarea
        aria-label="Message"
        value={input}
        onChange={(event) => onInputChange(event.target.value)}
        disabled={!canSend}
        placeholder={
          selectedConfigurationConnected
            ? "Ask a question"
            : "Connect a provider first"
        }
        variant="soft"
        textareaSize="lg"
        className="min-h-[104px] flex-1"
        onKeyDown={(event) => {
          if (event.key === "Enter" && !event.shiftKey) {
            event.preventDefault();
            void onSubmitText(input);
          }
        }}
      />
      <div className="flex items-center justify-between px-3 pb-3">
        <Button type="button" variant="outline" size="icon-sm" asChild>
          <Link href="/lighthouse/settings" aria-label="Lighthouse AI settings">
            <Settings className="size-4" />
          </Link>
        </Button>
        {isStreaming ? (
          <div
            className="flex size-8 items-center justify-center"
            role="status"
            aria-label="Generating response"
          >
            <Spinner className="size-4" />
          </div>
        ) : (
          <ChatSendButton canSend={canSend} hasText={input.trim().length > 0} />
        )}
      </div>
    </form>
  );
}

function ChatSendButton({
  canSend,
  hasText,
}: {
  canSend: boolean;
  hasText: boolean;
}) {
  const sendButton = (
    <Button type="submit" size="icon-sm" disabled={!canSend || !hasText}>
      <CornerDownLeft className="size-4" />
    </Button>
  );

  if (canSend && !hasText) {
    return (
      <Tooltip delayDuration={100}>
        <TooltipTrigger asChild>
          <span className="inline-flex cursor-not-allowed">{sendButton}</span>
        </TooltipTrigger>
        <TooltipContent side="top">Type something</TooltipContent>
      </Tooltip>
    );
  }

  return sendButton;
}
