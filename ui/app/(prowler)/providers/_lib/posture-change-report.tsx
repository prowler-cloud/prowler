"use client";

import { toast, ToastAction } from "@/components/shadcn/toast";
import { downloadFile } from "@/lib/helper";
import type { TaskKindHandler } from "@/store/task-watcher/store";

import { getPostureChangeReportBinary } from "../_actions/posture-change-report";

export const POSTURE_CHANGE_REPORT_TASK_KIND = "posture-change-report";
const downloadPostureChangeReport = async (taskId: string): Promise<void> => {
  try {
    const result = await getPostureChangeReportBinary(taskId);
    await downloadFile(
      result,
      "application/pdf",
      "The posture change report has been downloaded successfully.",
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

export const postureChangeReportHandler: TaskKindHandler = {
  onReady: (task) => {
    toast({
      title: "Posture change report ready",
      description: task.meta.reportLabel
        ? `The report for ${task.meta.reportLabel} has been generated.`
        : "The posture change report has been generated.",
      action: (
        <ToastAction
          altText="Download report"
          onClick={() => downloadPostureChangeReport(task.taskId)}
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
        "The posture change report could not be generated. Try again later.",
    });
  },
};
