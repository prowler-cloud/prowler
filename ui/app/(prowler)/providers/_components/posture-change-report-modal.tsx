"use client";

import { useState } from "react";

import { Label } from "@/components/shadcn";
import { Calendar } from "@/components/shadcn/calendar";
import { FormButtons } from "@/components/shadcn/form";
import { Input } from "@/components/shadcn/input/input";
import { Modal } from "@/components/shadcn/modal";
import { toast } from "@/components/shadcn/toast";
import { trackAndPollTask } from "@/store/task-watcher/store";

import { generatePostureChangeReport } from "../_actions/posture-change-report";
import {
  defaultPostureChangePeriod,
  type PostureChangePeriod,
  utcToday,
  validatePostureChangePeriod,
} from "../_lib/posture-change-period";
import { POSTURE_CHANGE_REPORT_TASK_KIND } from "../_lib/posture-change-report";

interface PostureChangeReportModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  providerId: string;
  providerLabel: string;
}

export const PostureChangeReportModal = ({
  open,
  onOpenChange,
  providerId,
  providerLabel,
}: PostureChangeReportModalProps) => (
  <Modal
    open={open}
    onOpenChange={onOpenChange}
    title="Generate Posture Change Report"
    description={`A PDF with how findings, inventory and compliance changed for ${providerLabel} between two dates (UTC).`}
    size="xl"
  >
    {open && (
      <PostureChangeReportForm
        providerId={providerId}
        providerLabel={providerLabel}
        onClose={() => onOpenChange(false)}
      />
    )}
  </Modal>
);

const PostureChangeReportForm = ({
  providerId,
  providerLabel,
  onClose,
}: {
  providerId: string;
  providerLabel: string;
  onClose: () => void;
}) => {
  const [today] = useState(() => utcToday(new Date()));
  const [period, setPeriod] = useState<PostureChangePeriod | undefined>(() =>
    defaultPostureChangePeriod(today),
  );
  const [reportName, setReportName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const validation = validatePostureChangePeriod(period, today);
  const periodError = "error" in validation ? validation.error : null;

  const handleSubmit = async () => {
    if ("error" in validation) return;
    setSubmitting(true);
    try {
      const result = await generatePostureChangeReport({
        providerId,
        ...validation,
        reportName: reportName.trim() || undefined,
      });
      if ("error" in result) {
        toast({
          variant: "destructive",
          title: "Could not start report generation",
          description: result.error,
        });
        return;
      }
      onClose();
      toast({
        title: "Report generation started",
        description:
          "We'll let you know when the PDF is ready. You can keep working meanwhile.",
      });
      await trackAndPollTask({
        taskId: result.taskId,
        kind: POSTURE_CHANGE_REPORT_TASK_KIND,
        meta: {
          providerId,
          reportLabel: reportName.trim() || providerLabel,
        },
      });
    } catch {
      toast({
        variant: "destructive",
        title: "Could not start report generation",
        description: "An unexpected error occurred. Please try again later.",
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        handleSubmit();
      }}
      className="flex flex-col gap-6"
    >
      <div className="flex flex-col gap-2">
        <Label>Period</Label>
        <Calendar
          mode="range"
          numberOfMonths={2}
          selected={
            period?.from ? { from: period.from, to: period.to } : undefined
          }
          onSelect={(range) => setPeriod(range)}
          defaultMonth={period?.from}
          disabled={{ after: today }}
        />
        {periodError && (
          <p role="alert" className="text-text-error-primary text-sm">
            {periodError}
          </p>
        )}
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="posture-change-report-name">Report name</Label>
        <Input
          id="posture-change-report-name"
          placeholder="Optional. A timestamped name is used by default"
          value={reportName}
          onChange={(event) => setReportName(event.target.value)}
        />
      </div>
      <FormButtons
        onCancel={onClose}
        submitText="Generate"
        loadingText="Starting..."
        isDisabled={submitting || Boolean(periodError)}
      />
    </form>
  );
};
