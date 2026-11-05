"use client";

import type { ScanBinaryResult } from "@/actions/scans/scans";
import { toast, ToastAction } from "@/components/shadcn/toast";
import { downloadFile } from "@/lib/helper";
import type { TaskKindHandler } from "@/store/task-watcher/store";

const normalizeScopeValue = (value: string | string[] | undefined) => {
  if (Array.isArray(value)) return [...value].sort();
  return (
    value
      ?.split(",")
      .map((item) => item.trim())
      .filter(Boolean)
      .sort()
      .join(",") ?? ""
  );
};

export const buildAggregatedCompliancePdfTaskScope = (
  values: Record<string, string | string[] | undefined>,
): string =>
  JSON.stringify(
    Object.fromEntries(
      Object.entries(values).map(([key, value]) => [
        key,
        normalizeScopeValue(value),
      ]),
    ),
  );

export const downloadAggregatedCompliancePdf = async ({
  taskId,
  getPdfBinary,
  axisLabel,
}: {
  taskId: string;
  getPdfBinary: (taskId: string) => Promise<ScanBinaryResult>;
  axisLabel: string;
}): Promise<void> => {
  try {
    const result = await getPdfBinary(taskId);
    await downloadFile(
      result,
      "application/pdf",
      `The ${axisLabel} compliance PDF has been downloaded successfully.`,
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

export const createAggregatedCompliancePdfHandler = ({
  axisLabel,
  downloadPdf,
}: {
  axisLabel: string;
  downloadPdf: (taskId: string) => Promise<void>;
}): TaskKindHandler => ({
  onReady: (task) => {
    toast({
      title: "Compliance report ready",
      description: task.meta.reportLabel
        ? `The ${task.meta.reportLabel} ${axisLabel} PDF has been generated.`
        : `The ${axisLabel} compliance PDF has been generated.`,
      action: (
        <ToastAction
          altText="Download report"
          onClick={() => downloadPdf(task.taskId)}
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
        `The ${axisLabel} PDF could not be generated. Try again later.`,
    });
  },
});
