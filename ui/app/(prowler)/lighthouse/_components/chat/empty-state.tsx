"use client";

import {
  BookOpen,
  FileCheck2,
  Network,
  Settings,
  ShieldAlert,
} from "lucide-react";
import Link from "next/link";
import { type FormEvent } from "react";

import { LighthouseIcon } from "@/components/icons/Icons";
import { Button } from "@/components/shadcn/button/button";

import { ChatComposerPanel } from "./composer";

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
    label: "Docs",
    prompt: "Point me to the relevant Prowler documentation for this task.",
    icon: BookOpen,
  },
] as const;

interface ChatEmptyStateProps {
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

export function ChatEmptyState({
  onInputChange,
  ...composerPanelProps
}: ChatEmptyStateProps) {
  return (
    <div className="flex min-h-0 flex-1 items-center justify-center px-4 py-10 md:px-8">
      <div className="mx-auto flex w-full max-w-5xl flex-col items-center gap-5">
        <LighthouseIcon className="size-12" />
        <div className="space-y-2 text-center">
          <h1 className="text-text-neutral-primary text-3xl font-semibold">
            What do you want to know today?
          </h1>
          <p className="text-text-neutral-secondary text-base italic">
            Understand and secure your cloud.
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
            Try Lighthouse for...
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
          <Button type="button" variant="outline" size="icon-sm" asChild>
            <Link href="/lighthouse/settings" aria-label="Lighthouse settings">
              <Settings className="size-4" />
            </Link>
          </Button>
        </div>
      </div>
    </div>
  );
}
