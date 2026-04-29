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
  /** Enable multiline display (disables truncation, enables word wrap) */
  multiline?: boolean;
  /** Remove background and border */
  transparent?: boolean;
  /** Custom aria-label for the copy button */
  ariaLabel?: string;
}

export const CodeSnippet = ({
  value,
  className,
  hideCode = false,
  hideCopyButton = false,
  icon,
  formatter,
  transparent = false,
  multiline = false,
  ariaLabel = "Copy to clipboard",
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
      aria-label={ariaLabel}
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
        aria-label={ariaLabel}
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
        "flex w-fit min-w-0 items-center gap-1.5 text-xs",
        transparent
          ? "text-text-neutral-tertiary border-0 bg-transparent px-0 py-0"
          : "text-text-neutral-primary bg-bg-neutral-tertiary border-border-neutral-tertiary border-2 px-2 py-0.5",
        multiline
          ? "h-auto rounded-lg"
          : transparent
            ? "h-auto"
            : "h-6 rounded-full",
        className,
      )}
    >
      {icon && (
        <span className="text-text-neutral-secondary shrink-0">{icon}</span>
      )}
      {multiline ? (
        <span className="min-w-0 flex-1 break-all whitespace-pre-wrap">
          {displayValue}
        </span>
      ) : (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="min-w-0 flex-1 truncate">{displayValue}</span>
          </TooltipTrigger>
          <TooltipContent side="top">{value}</TooltipContent>
        </Tooltip>
      )}
      {!hideCopyButton && <CopyButton />}
    </div>
  );
};
