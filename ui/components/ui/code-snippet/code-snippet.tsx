"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";

import { cn } from "@/lib/utils";

interface CodeSnippetProps {
  value: string;
  className?: string;
}

export const CodeSnippet = ({ value, className }: CodeSnippetProps) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className={cn(
        "bg-bg-neutral-tertiary text-text-neutral-primary border-border-neutral-tertiary flex w-full items-center justify-between gap-2 rounded-lg border px-3 py-1 text-xs",
        className,
      )}
    >
      <code className="truncate">{value}</code>
      <button
        type="button"
        onClick={handleCopy}
        className="text-text-neutral-secondary hover:text-text-neutral-primary shrink-0 cursor-pointer transition-colors"
        aria-label="Copy to clipboard"
      >
        {copied ? (
          <Check className="h-3.5 w-3.5" />
        ) : (
          <Copy className="h-3.5 w-3.5" />
        )}
      </button>
    </div>
  );
};
