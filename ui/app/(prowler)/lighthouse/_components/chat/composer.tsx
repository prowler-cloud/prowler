"use client";

import { ArrowRight, Square } from "lucide-react";
import { type FormEvent } from "react";

import { Button } from "@/components/shadcn/button/button";
import { Textarea } from "@/components/shadcn/textarea/textarea";

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
  onStop,
  onSubmit,
  onSubmitText,
}: ChatComposerProps) {
  return (
    <form
      className="border-border-neutral-secondary bg-bg-neutral-secondary flex min-h-[150px] w-full flex-col rounded-[8px] border shadow-xs"
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
        variant="ghost"
        textareaSize="lg"
        className="min-h-[104px] flex-1 rounded-b-none border-0 hover:bg-transparent focus:bg-transparent focus:ring-0"
        onKeyDown={(event) => {
          if (event.key === "Enter" && !event.shiftKey) {
            event.preventDefault();
            void onSubmitText(input);
          }
        }}
      />
      <div className="flex items-center justify-end px-3 pb-3">
        {isStreaming ? (
          <Button
            type="button"
            variant="outline"
            size="icon-sm"
            onClick={onStop}
          >
            <Square className="size-4" />
          </Button>
        ) : (
          <Button
            type="submit"
            size="icon-sm"
            disabled={!canSend || !input.trim()}
          >
            <ArrowRight className="size-4" />
          </Button>
        )}
      </div>
    </form>
  );
}
