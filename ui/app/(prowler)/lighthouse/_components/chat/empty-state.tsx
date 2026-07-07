"use client";

import { Cloud, FileCheck2, Network, ShieldAlert } from "lucide-react";
import { type ReactNode, type SubmitEvent } from "react";

import { LighthouseIconWithAura } from "@/components/icons";
import { Button } from "@/components/shadcn/button/button";

import { ChatComposerPanel } from "./composer";
import { DecryptedText } from "./decrypted-text";

const LIGHTHOUSE_V2_SUGGESTIONS = [
  {
    label: "Critical findings",
    prompt: "Summarize my most critical open findings and what to fix first.",
    icon: ShieldAlert,
  },
  {
    label: "Compliance gaps",
    prompt: "What are my highest-impact compliance gaps right now?",
    icon: FileCheck2,
  },
  {
    label: "Attack paths",
    prompt: "Find risky attack paths and explain the exposure.",
    icon: Network,
  },
  {
    label: "How can I onboard to my AWS account?",
    prompt: "How can I onboard to my AWS account?",
    icon: Cloud,
  },
] as const;

interface ChatEmptyStateProps {
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
  footer?: ReactNode;
  // Side-panel variant: smaller logo and static (non-animated) copy — the
  // decrypt animation reflows multi-line text in narrow widths.
  compact?: boolean;
}

export function ChatEmptyState({
  onInputChange,
  footer,
  compact = false,
  ...composerPanelProps
}: ChatEmptyStateProps) {
  return (
    <div className="flex min-h-0 flex-1 items-center justify-center px-4 py-10 md:px-8">
      <div className="mx-auto flex w-full max-w-5xl flex-col items-center gap-5">
        <LighthouseIconWithAura className={compact ? "size-12" : "size-20"} />
        <div className="space-y-2 text-center">
          <h1
            className={
              compact
                ? "text-text-neutral-primary text-lg font-semibold"
                : "text-text-neutral-primary text-3xl font-semibold"
            }
          >
            {compact ? (
              "Find and remediate which actually matters."
            ) : (
              <DecryptedText
                text="Find and remediate which actually matters."
                animateOn="view"
                sequential
                speed={40}
                encryptedClassName="text-text-neutral-tertiary"
              />
            )}
          </h1>
          <p
            className={
              compact
                ? "text-text-neutral-secondary text-sm italic"
                : "text-text-neutral-secondary text-base italic"
            }
          >
            {compact ? (
              "What do you want to know today?"
            ) : (
              <DecryptedText
                text="What do you want to know today?"
                animateOn="view"
                sequential
                speed={40}
                encryptedClassName="text-text-neutral-tertiary"
              />
            )}
          </p>
        </div>
        <div className="w-full max-w-4xl">
          <ChatComposerPanel
            {...composerPanelProps}
            onInputChange={onInputChange}
          />
        </div>
        <div className="flex max-w-4xl flex-wrap items-center justify-center gap-2">
          <span className="text-text-neutral-secondary basis-full text-center text-sm font-medium">
            Try Lighthouse AI for...
          </span>
          {LIGHTHOUSE_V2_SUGGESTIONS.map((suggestion) => {
            const Icon = suggestion.icon;
            return (
              <Button
                key={suggestion.label}
                type="button"
                variant="outline"
                size="sm"
                onClick={() => onInputChange(suggestion.prompt)}
              >
                <Icon className="size-4" />
                {suggestion.label}
              </Button>
            );
          })}
        </div>
        {footer ? <div className="w-full max-w-4xl">{footer}</div> : null}
      </div>
    </div>
  );
}
