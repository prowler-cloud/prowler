"use client";

import { Progress } from "@heroui/progress";
import Link from "next/link";
import { useState } from "react";

import {
  AlertCircleIcon,
  CheckCircleIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  DatabaseIcon,
  ExternalLinkIcon,
  FileSearchIcon,
  FileTextIcon,
  Loader2Icon,
  ServerIcon,
  SettingsIcon,
  XIcon,
} from "@/components/icons";
import { Button } from "@/components/shadcn/button/button";
import { cn } from "@/lib/utils";

import type { ImportScanError, ProcessingStep, ScanImportProgressProps } from "./types";

/**
 * Formats a number with thousand separators.
 */
function formatNumber(num: number): string {
  return num.toLocaleString();
}

/**
 * Get the icon for a processing step.
 */
function getStepIcon(step: ProcessingStep, isActive: boolean) {
  const iconClass = cn(
    "h-4 w-4",
    isActive ? "text-button-primary" : "text-text-neutral-tertiary"
  );

  switch (step) {
    case "parsing":
      return <FileSearchIcon className={iconClass} />;
    case "validating":
      return <FileTextIcon className={iconClass} />;
    case "resolving-provider":
      return <ServerIcon className={iconClass} />;
    case "creating-resources":
      return <DatabaseIcon className={iconClass} />;
    case "creating-findings":
      return <FileTextIcon className={iconClass} />;
    case "finalizing":
      return <SettingsIcon className={iconClass} />;
    default:
      return <Loader2Icon className={cn(iconClass, isActive && "animate-spin")} />;
  }
}

/**
 * Get the display label for a processing step.
 */
function getStepLabel(step: ProcessingStep): string {
  switch (step) {
    case "parsing":
      return "Parsing file";
    case "validating":
      return "Validating data";
    case "resolving-provider":
      return "Resolving provider";
    case "creating-resources":
      return "Creating resources";
    case "creating-findings":
      return "Creating findings";
    case "finalizing":
      return "Finalizing import";
    default:
      return "Processing";
  }
}

/**
 * Processing steps in order for display.
 */
const PROCESSING_STEPS: ProcessingStep[] = [
  "parsing",
  "validating",
  "resolving-provider",
  "creating-resources",
  "creating-findings",
  "finalizing",
];

/**
 * Progress component for displaying scan import status.
 *
 * Shows different states:
 * - idle: Nothing displayed
 * - uploading: Upload progress bar
 * - processing: Processing indicator with step details
 * - completed: Success message with scan link
 * - error: Error message with details
 */
export function ScanImportProgress({
  status,
  progress = 0,
  processingStep,
  result,
  error,
  errors,
  onReset,
}: ScanImportProgressProps) {
  // State for expanding/collapsing error details
  const [showAllErrors, setShowAllErrors] = useState(false);

  // Combine single error and errors array for unified handling
  const allErrors: ImportScanError[] = errors?.length
    ? errors
    : error
      ? [error]
      : [];

  // Don't render anything in idle state
  if (status === "idle") {
    return null;
  }

  // Get current step index for progress calculation
  const currentStepIndex = processingStep?.step
    ? PROCESSING_STEPS.indexOf(processingStep.step)
    : 0;
  const processingProgress = Math.round(
    ((currentStepIndex + 1) / PROCESSING_STEPS.length) * 100
  );

  return (
    <div
      className={cn(
        "rounded-lg border p-4",
        "transition-all duration-200 ease-in-out",
        status === "completed" && "border-bg-pass bg-bg-pass/5",
        status === "error" && "border-bg-fail bg-bg-fail/5",
        (status === "uploading" || status === "processing") &&
          "border-border-neutral-secondary bg-bg-neutral-secondary"
      )}
      role="status"
      aria-live="polite"
    >
      {/* Uploading State */}
      {status === "uploading" && (
        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-button-primary/10">
              <Loader2Icon className="h-5 w-5 animate-spin text-button-primary" />
            </div>
            <div className="flex-1">
              <p className="text-sm font-medium text-text-neutral-primary">
                Uploading scan results...
              </p>
              <p className="text-xs text-text-neutral-secondary">
                {progress}% complete
              </p>
            </div>
          </div>
          <Progress
            aria-label="Upload progress"
            value={progress}
            size="sm"
            classNames={{
              track: "drop-shadow-sm border border-default",
              indicator: "bg-button-primary",
            }}
          />
        </div>
      )}

      {/* Processing State */}
      {status === "processing" && (
        <div className="flex flex-col gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-button-primary/10">
              <Loader2Icon className="h-5 w-5 animate-spin text-button-primary" />
            </div>
            <div className="flex-1">
              <p className="text-sm font-medium text-text-neutral-primary">
                Processing scan data...
              </p>
              <p className="text-xs text-text-neutral-secondary">
                {processingStep?.message ||
                  (processingStep?.step
                    ? getStepLabel(processingStep.step)
                    : "Creating findings and resources")}
              </p>
            </div>
          </div>

          {/* Processing Progress Bar */}
          <Progress
            aria-label="Processing progress"
            value={processingProgress}
            size="sm"
            classNames={{
              track: "drop-shadow-sm border border-default",
              indicator: "bg-button-primary",
            }}
          />

          {/* Processing Steps */}
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {PROCESSING_STEPS.map((step, index) => {
              const isCompleted = index < currentStepIndex;
              const isActive =
                processingStep?.step === step || index === currentStepIndex;
              const isPending = index > currentStepIndex;

              return (
                <div
                  key={step}
                  className={cn(
                    "flex items-center gap-2 rounded-md px-2 py-1.5",
                    "transition-all duration-200",
                    isActive && "bg-button-primary/10",
                    isCompleted && "opacity-60"
                  )}
                >
                  {isCompleted ? (
                    <CheckCircleIcon className="h-4 w-4 text-bg-pass" />
                  ) : isActive ? (
                    <Loader2Icon className="h-4 w-4 animate-spin text-button-primary" />
                  ) : (
                    getStepIcon(step, false)
                  )}
                  <span
                    className={cn(
                      "text-xs",
                      isActive
                        ? "font-medium text-text-neutral-primary"
                        : isPending
                          ? "text-text-neutral-tertiary"
                          : "text-text-neutral-secondary"
                    )}
                  >
                    {getStepLabel(step)}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Success State */}
      {status === "completed" && result && (
        <div className="flex flex-col gap-4">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-start gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-bg-pass/10">
                <CheckCircleIcon className="h-5 w-5 text-bg-pass" />
              </div>
              <div>
                <p className="text-sm font-medium text-text-neutral-primary">
                  Import completed successfully
                </p>
                <p className="mt-1 text-xs text-text-neutral-secondary">
                  Your scan results have been imported
                </p>
              </div>
            </div>
            {onReset && (
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                onClick={onReset}
                aria-label="Dismiss"
              >
                <XIcon className="h-4 w-4" />
              </Button>
            )}
          </div>

          {/* Import Statistics */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="rounded-md bg-bg-neutral-secondary p-3">
              <p className="text-xs text-text-neutral-secondary">Findings</p>
              <p className="text-lg font-semibold text-text-neutral-primary">
                {formatNumber(result.findingsCount)}
              </p>
            </div>
            <div className="rounded-md bg-bg-neutral-secondary p-3">
              <p className="text-xs text-text-neutral-secondary">Resources</p>
              <p className="text-lg font-semibold text-text-neutral-primary">
                {formatNumber(result.resourcesCount)}
              </p>
            </div>
            <div className="rounded-md bg-bg-neutral-secondary p-3 sm:col-span-2">
              <p className="text-xs text-text-neutral-secondary">Provider</p>
              <p className="truncate text-sm font-medium text-text-neutral-primary">
                {result.providerCreated ? "Created new" : "Existing"}
              </p>
            </div>
          </div>

          {/* Warnings if any */}
          {result.warnings && result.warnings.length > 0 && (
            <div className="rounded-md border border-yellow-500/30 bg-yellow-500/5 p-3">
              <p className="mb-1 text-xs font-medium text-yellow-600 dark:text-yellow-400">
                Warnings ({result.warnings.length})
              </p>
              <ul className="space-y-1">
                {result.warnings.slice(0, 3).map((warning, index) => (
                  <li
                    key={index}
                    className="text-xs text-text-neutral-secondary"
                  >
                    • {warning}
                  </li>
                ))}
                {result.warnings.length > 3 && (
                  <li className="text-xs text-text-neutral-tertiary">
                    ...and {result.warnings.length - 3} more
                  </li>
                )}
              </ul>
            </div>
          )}

          {/* View Scan Link */}
          <Link
            href={`/scans/${result.scanId}`}
            className={cn(
              "inline-flex items-center justify-center gap-2 rounded-md px-4 py-2",
              "bg-button-primary text-sm font-medium text-black",
              "hover:bg-button-primary-hover",
              "focus:outline-none focus:ring-2 focus:ring-button-primary/50 focus:ring-offset-2",
              "transition-all duration-200 ease-in-out"
            )}
          >
            <FileTextIcon className="h-4 w-4" />
            View Imported Scan
            <ExternalLinkIcon className="h-3 w-3" />
          </Link>
        </div>
      )}

      {/* Error State */}
      {status === "error" && allErrors.length > 0 && (
        <div className="flex flex-col gap-3">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-start gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-bg-fail/10">
                <AlertCircleIcon className="h-5 w-5 text-bg-fail" />
              </div>
              <div>
                <p className="text-sm font-medium text-text-neutral-primary">
                  {allErrors[0]?.title || "Import failed"}
                </p>
                <p className="mt-1 text-xs text-text-neutral-secondary">
                  {allErrors[0]?.detail ||
                    "An error occurred while importing the scan"}
                </p>
              </div>
            </div>
            {onReset && (
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                onClick={onReset}
                aria-label="Dismiss"
              >
                <XIcon className="h-4 w-4" />
              </Button>
            )}
          </div>

          {/* Primary Error Details */}
          {allErrors[0]?.source?.pointer && (
            <div className="rounded-md bg-bg-neutral-secondary p-3">
              <p className="text-xs text-text-neutral-secondary">
                Error location
              </p>
              <code className="mt-1 block break-all text-xs text-text-neutral-primary">
                {allErrors[0].source.pointer}
              </code>
            </div>
          )}

          {/* Primary Error Code */}
          {allErrors[0]?.code && (
            <p className="text-xs text-text-neutral-tertiary">
              Error code: {allErrors[0].code}
            </p>
          )}

          {/* Additional Errors Section */}
          {allErrors.length > 1 && (
            <div className="rounded-md border border-bg-fail/20 bg-bg-fail/5 p-3">
              <button
                type="button"
                onClick={() => setShowAllErrors(!showAllErrors)}
                className="flex w-full items-center justify-between text-left"
                aria-expanded={showAllErrors}
              >
                <span className="text-xs font-medium text-bg-fail">
                  {allErrors.length - 1} additional error
                  {allErrors.length > 2 ? "s" : ""}
                </span>
                {showAllErrors ? (
                  <ChevronUpIcon className="h-4 w-4 text-bg-fail" />
                ) : (
                  <ChevronDownIcon className="h-4 w-4 text-bg-fail" />
                )}
              </button>

              {showAllErrors && (
                <div className="mt-3 space-y-3">
                  {allErrors.slice(1).map((err, index) => (
                    <div
                      key={index}
                      className="border-t border-bg-fail/10 pt-3 first:border-t-0 first:pt-0"
                    >
                      <p className="text-xs font-medium text-text-neutral-primary">
                        {err.title || "Error"}
                      </p>
                      <p className="mt-0.5 text-xs text-text-neutral-secondary">
                        {err.detail}
                      </p>
                      {err.source?.pointer && (
                        <code className="mt-1 block break-all text-xs text-text-neutral-tertiary">
                          Location: {err.source.pointer}
                        </code>
                      )}
                      {err.code && (
                        <p className="mt-0.5 text-xs text-text-neutral-tertiary">
                          Code: {err.code}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Validation Error Summary */}
          {allErrors.some((e) => e.code === "validation_error") && (
            <div className="rounded-md bg-bg-neutral-secondary p-3">
              <p className="text-xs font-medium text-text-neutral-secondary">
                Troubleshooting tips
              </p>
              <ul className="mt-2 space-y-1 text-xs text-text-neutral-secondary">
                <li>• Ensure the file is a valid Prowler JSON (OCSF) or CSV output</li>
                <li>• Check that all required fields are present in the file</li>
                <li>• Verify the file is not corrupted or truncated</li>
              </ul>
            </div>
          )}

          {/* Try Again Button */}
          {onReset && (
            <Button
              type="button"
              variant="outline"
              onClick={onReset}
              className="w-full"
            >
              Try Again
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
