"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useRouter } from "next/navigation";
import { useCallback, useState } from "react";

import { importScan } from "@/actions/scans/import-scan";
import { ChevronDownIcon, ChevronUpIcon, UploadIcon } from "@/components/icons";
import { Button } from "@/components/shadcn/button/button";
import { cn } from "@/lib/utils";
import { ProviderType } from "@/types/providers";

import { ScanImportForm } from "./scan-import-form";
import { ScanImportProgress } from "./scan-import-progress";
import type {
  ImportScanError,
  ImportScanResult,
  ImportStatus,
  ProcessingStepInfo,
  ScanImportFormData,
  ScanImportSectionProps,
} from "./types";

/**
 * Provider info type for the import section.
 */
interface ProviderInfo {
  id: string;
  provider: ProviderType;
  uid: string;
  alias: string;
}

/**
 * Props for the ScanImportSection component with providers.
 */
interface ScanImportSectionWithProvidersProps extends ScanImportSectionProps {
  /** Available providers for selection */
  providers?: ProviderInfo[];
}

/**
 * Main section component for importing scan results.
 *
 * Composes the dropzone, form, and progress components to provide
 * a complete scan import experience. Manages the upload state machine
 * and handles form submission.
 *
 * States:
 * - idle: Initial state, form is visible
 * - uploading: File is being uploaded to the server
 * - processing: Server is processing the scan data
 * - completed: Import finished successfully
 * - error: Import failed with errors
 */
export function ScanImportSection({
  onImportComplete,
  providers = [],
}: ScanImportSectionWithProvidersProps) {
  const router = useRouter();

  // Collapsible state
  const [isExpanded, setIsExpanded] = useState(false);

  // Upload state machine
  const [status, setStatus] = useState<ImportStatus>("idle");
  const [progress, setProgress] = useState(0);
  const [processingStep, setProcessingStep] = useState<
    ProcessingStepInfo | undefined
  >();
  const [result, setResult] = useState<ImportScanResult | undefined>();
  const [error, setError] = useState<ImportScanError | undefined>();

  /**
   * Resets the import state to idle.
   */
  const handleReset = useCallback(() => {
    setStatus("idle");
    setProgress(0);
    setProcessingStep(undefined);
    setResult(undefined);
    setError(undefined);
  }, []);

  /**
   * Handles form submission and import process.
   */
  const handleSubmit = useCallback(
    async (data: ScanImportFormData) => {
      if (!data.file) {
        setError({
          title: "No file selected",
          detail: "Please select a file to import",
        });
        setStatus("error");
        return;
      }

      try {
        // Start upload
        setStatus("uploading");
        setProgress(0);
        setError(undefined);

        // Simulate upload progress (actual upload happens in server action)
        const progressInterval = setInterval(() => {
          setProgress((prev) => {
            if (prev >= 90) {
              clearInterval(progressInterval);
              return 90;
            }
            return prev + 10;
          });
        }, 100);

        // Build form data for server action
        const formData = new FormData();
        formData.append("file", data.file);
        if (data.providerId) {
          formData.append("providerId", data.providerId);
        }
        formData.append("createProvider", String(data.createProvider));

        // Complete upload progress
        clearInterval(progressInterval);
        setProgress(100);

        // Switch to processing state
        setStatus("processing");
        setProcessingStep({ step: "parsing", message: "Parsing file..." });

        // Simulate processing steps for better UX
        const steps: Array<{
          step: ProcessingStepInfo["step"];
          message: string;
        }> = [
          { step: "validating", message: "Validating data..." },
          { step: "resolving-provider", message: "Resolving provider..." },
          { step: "creating-resources", message: "Creating resources..." },
          { step: "creating-findings", message: "Creating findings..." },
          { step: "finalizing", message: "Finalizing import..." },
        ];

        // Start the actual import
        const importPromise = importScan(formData);

        // Simulate step progression while waiting for response
        let stepIndex = 0;
        const stepInterval = setInterval(() => {
          if (stepIndex < steps.length) {
            setProcessingStep(steps[stepIndex]);
            stepIndex++;
          } else {
            clearInterval(stepInterval);
          }
        }, 500);

        // Wait for import result
        const importResult = await importPromise;
        clearInterval(stepInterval);

        if (importResult.success) {
          setResult(importResult.data);
          setStatus("completed");
          // Refresh the page to update the scan list
          router.refresh();
          onImportComplete?.(importResult.data.scanId);
        } else {
          setError({
            title: "Import failed",
            detail: importResult.error,
          });
          setStatus("error");
        }
      } catch (err) {
        console.error("Import error:", err);
        setError({
          title: "Import failed",
          detail:
            err instanceof Error ? err.message : "An unexpected error occurred",
        });
        setStatus("error");
      }
    },
    [onImportComplete, router],
  );

  const isSubmitting = status === "uploading" || status === "processing";

  return (
    <div className="w-full">
      {/* Collapsible Header */}
      <button
        type="button"
        onClick={() => setIsExpanded(!isExpanded)}
        className={cn(
          "flex w-full items-center justify-between rounded-lg px-4 py-3",
          "bg-bg-neutral-secondary border-border-neutral-secondary border",
          "hover:bg-bg-neutral-tertiary hover:border-border-neutral-tertiary",
          "focus-visible:ring-button-primary/50 focus:outline-none focus-visible:ring-2",
          "transition-all duration-200 ease-in-out",
          isExpanded && "rounded-b-none border-b-0",
        )}
        aria-expanded={isExpanded}
        aria-controls="scan-import-content"
      >
        <div className="flex items-center gap-3">
          <div className="bg-button-primary/10 flex h-8 w-8 items-center justify-center rounded-md">
            <UploadIcon className="text-button-primary h-4 w-4" />
          </div>
          <div className="text-left">
            <p className="text-text-neutral-primary text-sm font-medium">
              Import Scan Results
            </p>
            <p className="text-text-neutral-secondary text-xs">
              Upload Prowler CLI output (JSON or CSV)
            </p>
          </div>
        </div>
        {isExpanded ? (
          <ChevronUpIcon className="text-text-neutral-secondary h-5 w-5" />
        ) : (
          <ChevronDownIcon className="text-text-neutral-secondary h-5 w-5" />
        )}
      </button>

      {/* Collapsible Content */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            id="scan-import-content"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: "easeInOut" }}
            className="overflow-hidden"
          >
            <div
              className={cn(
                "border-border-neutral-secondary rounded-b-lg border border-t-0",
                "bg-bg-neutral-secondary p-4",
              )}
            >
              {/* Progress Display (when not idle) */}
              {status !== "idle" && (
                <div className="mb-4">
                  <ScanImportProgress
                    status={status}
                    progress={progress}
                    processingStep={processingStep}
                    result={result}
                    error={error}
                    onReset={handleReset}
                  />
                </div>
              )}

              {/* Form (when idle or error) */}
              {(status === "idle" || status === "error") && (
                <ScanImportForm
                  onSubmit={handleSubmit}
                  isSubmitting={isSubmitting}
                  providers={providers}
                />
              )}

              {/* Reset button when completed */}
              {status === "completed" && (
                <div className="mt-4">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={handleReset}
                    className="w-full"
                  >
                    Import Another Scan
                  </Button>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
