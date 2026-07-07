"use client";

import { CornerDownLeft, Settings, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { type ReactNode, type SubmitEvent, useRef } from "react";

import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { Textarea } from "@/components/shadcn/textarea/textarea";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";

interface ChatComposerPanelProps {
  feedback: string | null;
  canRetry: boolean;
  onRetry: () => void;
  onDismissFeedback: () => void;
  canSend: boolean;
  input: string;
  isStreaming: boolean;
  modelSelector: ReactNode;
  selectedConfigurationConnected: boolean;
  onInputChange: (value: string) => void;
  onSubmit: (event: SubmitEvent<HTMLFormElement>) => void;
  onSubmitText: (text: string) => Promise<void>;
}

// Feedback banner + input, shared by the empty and active chat layouts so the
// two branches can't drift apart.
export function ChatComposerPanel({
  feedback,
  canRetry,
  onRetry,
  onDismissFeedback,
  ...composerProps
}: ChatComposerPanelProps) {
  return (
    <>
      <ChatFeedbackBar
        feedback={feedback}
        canRetry={canRetry}
        onRetry={onRetry}
        onDismiss={onDismissFeedback}
      />
      <ChatComposer {...composerProps} />
    </>
  );
}

function ChatFeedbackBar({
  feedback,
  canRetry,
  onRetry,
  onDismiss,
}: {
  feedback: string | null;
  canRetry: boolean;
  onRetry: () => void;
  onDismiss: () => void;
}) {
  if (!feedback) return null;

  return (
    <Alert variant="error" onClose={onDismiss} className="mb-3 pr-10">
      <TriangleAlert />
      <AlertDescription className="flex items-center justify-between gap-3">
        <span>{feedback}</span>
        {canRetry && (
          <Button type="button" variant="outline" size="sm" onClick={onRetry}>
            Retry
          </Button>
        )}
      </AlertDescription>
    </Alert>
  );
}

interface ChatComposerProps {
  canSend: boolean;
  input: string;
  isStreaming: boolean;
  modelSelector: ReactNode;
  selectedConfigurationConnected: boolean;
  onInputChange: (value: string) => void;
  onSubmit: (event: SubmitEvent<HTMLFormElement>) => void;
  onSubmitText: (text: string) => Promise<void>;
}

function ChatComposer({
  canSend,
  input,
  isStreaming,
  selectedConfigurationConnected,
  onInputChange,
  modelSelector,
  onSubmit,
  onSubmitText,
}: ChatComposerProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useMountEffect(() => {
    textareaRef.current?.focus();
  });

  return (
    <form
      className="border-border-neutral-secondary bg-bg-neutral-tertiary has-[textarea:focus]:border-border-input-primary-press flex min-h-[150px] w-full flex-col overflow-hidden rounded-[8px] border shadow-xs transition-all"
      onSubmit={onSubmit}
    >
      <Textarea
        ref={textareaRef}
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
          // Ignore Enter while an IME composition is active so confirming an
          // East Asian candidate doesn't submit the message prematurely.
          if (
            event.key === "Enter" &&
            !event.shiftKey &&
            !event.nativeEvent.isComposing
          ) {
            event.preventDefault();
            void onSubmitText(input);
          }
        }}
      />
      <div className="flex items-center justify-between gap-3 px-3 pb-3">
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <Button type="button" variant="outline" size="icon-sm" asChild>
            <Link
              href={LIGHTHOUSE_ROUTE.SETTINGS}
              aria-label="Lighthouse AI settings"
            >
              <Settings className="size-4" />
            </Link>
          </Button>
          {modelSelector}
        </div>
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
