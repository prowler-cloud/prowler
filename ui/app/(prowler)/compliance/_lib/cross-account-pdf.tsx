"use client";

import { toast, ToastAction } from "@/components/shadcn/toast";
import { downloadFile } from "@/lib/helper";
import type { TaskKindHandler } from "@/store/task-watcher/store";

import { getCrossAccountPdfBinary } from "../_actions/cross-account";
import type { CrossAccountApiFilters } from "../_types";

export const CROSS_ACCOUNT_PDF_TASK_KIND = "cross-account-pdf";

const normalizeCommaSeparatedFilter = (value?: string): string =>
  value
    ?.split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .sort()
    .join(",") ?? "";

/** Stable identity for the exact cross-account view a PDF represents. */
export const buildCrossAccountPdfTaskScope = (
  complianceId: string,
  providerType: string,
  filters: CrossAccountApiFilters,
): string =>
  JSON.stringify({
    complianceId,
    providerType,
    scanIds: [...(filters.scanIds ?? [])].sort(),
    providerIds: normalizeCommaSeparatedFilter(filters.providerIds),
    providerGroups: normalizeCommaSeparatedFilter(filters.providerGroups),
  });

/** Fetches the finished cross-account PDF and hands it to the browser —
 *  same never-rejects contract as `downloadCrossProviderPdf`. */
export const downloadCrossAccountPdf = async (
  taskId: string,
): Promise<void> => {
  try {
    const result = await getCrossAccountPdfBinary(taskId);
    await downloadFile(
      result,
      "application/pdf",
      "The cross-account compliance PDF has been downloaded successfully.",
      toast,
    );
  } catch {
    toast({
      variant: "destructive",
      title: "Download failed",
      description: "Could not fetch the report. Please try again later.",
    });
  }
};

/** Completion handler for cross-account PDF generation tasks, fired by the
 *  generic task watcher — survives navigation and hard reloads like its
 *  cross-provider sibling. */
export const crossAccountPdfHandler: TaskKindHandler = {
  onReady: (task) => {
    toast({
      title: "Compliance report ready",
      description: task.meta.reportLabel
        ? `The ${task.meta.reportLabel} cross-account PDF has been generated.`
        : "The cross-account compliance PDF has been generated.",
      action: (
        <ToastAction
          altText="Download report"
          onClick={() => downloadCrossAccountPdf(task.taskId)}
        >
          Download
        </ToastAction>
      ),
    });
  },
  onError: (task) => {
    toast({
      variant: "destructive",
      title: "Report generation failed",
      description:
        task.error ||
        "The cross-account PDF could not be generated. Try again later.",
    });
  },
};
