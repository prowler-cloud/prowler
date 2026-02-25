"use client";

import { Check, Copy } from "lucide-react";
import { ReactNode, useState } from "react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";

interface CodeSnippetProps {
  value: string;
  className?: string;
  /** Hide the code text and show only the copy button */
  hideCode?: boolean;
  /** Hide the copy button */
  hideCopyButton?: boolean;
  /** Icon to display before the text */
  icon?: ReactNode;
  /** Function to format the displayed text (value is still copied as-is) */
  formatter?: (value: string) => string;
}

export const CodeSnippet = ({
  value,
  className,
  hideCode = false,
  hideCopyButton = false,
  icon,
  formatter,
}: CodeSnippetProps) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const displayValue = formatter ? formatter(value) : value;

  const CopyButton = () => (
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
  );

  // When hideCode is true, render only the copy button without container styling
  if (hideCode) {
    return (
      <button
        type="button"
        onClick={handleCopy}
        className={cn(
          "hover:bg-bg-neutral-tertiary text-text-neutral-secondary hover:text-text-neutral-primary shrink-0 cursor-pointer rounded-md p-1 transition-colors",
          className,
        )}
        aria-label="Copy to clipboard"
      >
        {copied ? (
          <Check className="h-3.5 w-3.5" />
        ) : (
          <Copy className="h-3.5 w-3.5" />
        )}
      </button>
    );
  }

  return (
    <div
      className={cn(
        "bg-bg-neutral-tertiary text-text-neutral-primary border-border-neutral-tertiary flex h-6 w-fit items-center gap-2 rounded-lg border px-2 py-1 text-xs",
        className,
      )}
    >
      {icon && (
        <span className="text-text-neutral-secondary shrink-0">{icon}</span>
      )}
      <Tooltip>
        <TooltipTrigger asChild>
          <code className="min-w-0 flex-1 truncate">{displayValue}</code>
        </TooltipTrigger>
        <TooltipContent side="top">{value}</TooltipContent>
      </Tooltip>
      {!hideCopyButton && <CopyButton />}
    </div>
  );
};
