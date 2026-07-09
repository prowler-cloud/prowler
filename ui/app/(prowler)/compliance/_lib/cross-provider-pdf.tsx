"use client";

import { toast, ToastAction } from "@/components/shadcn/toast";
import { downloadFile } from "@/lib/helper";
import type { TaskKindHandler } from "@/store/task-watcher/store";

import { getCrossProviderPdfBinary } from "../_actions/cross-provider";

export const CROSS_PROVIDER_PDF_TASK_KIND = "cross-provider-pdf";

/** Fetches the finished cross-provider PDF and hands it to the browser,
 *  reusing the shared base64→blob download + toast handling. */
export const downloadCrossProviderPdf = async (
  taskId: string,
): Promise<void> => {
  const result = await getCrossProviderPdfBinary(taskId);
  await downloadFile(
    result,
    "application/pdf",
    "The cross-provider compliance PDF has been downloaded successfully.",
    toast,
  );
};

/**
 * Completion handler for cross-provider PDF generation tasks. Fired by the
 * generic task watcher (`@/store/task-watcher`) whenever a tracked task of
 * this kind settles — including after client-side navigation (module-scope
 * poll loop) or a hard reload (persisted store + `TaskPollingWatcher`).
 */
export const crossProviderPdfHandler: TaskKindHandler = {
  onReady: (task) => {
    toast({
      title: "Compliance report ready",
      description: task.meta.reportLabel
        ? `The ${task.meta.reportLabel} cross-provider PDF has been generated.`
        : "The cross-provider compliance PDF has been generated.",
      action: (
        <ToastAction
          altText="Download report"
          onClick={() => downloadCrossProviderPdf(task.taskId)}
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
        "The cross-provider PDF could not be generated. Try again later.",
    });
  },
};
