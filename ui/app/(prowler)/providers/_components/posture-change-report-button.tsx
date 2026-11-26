"use client";

import { FileChartLine } from "lucide-react";
import { useState } from "react";

import { AccountsSelector } from "@/app/(prowler)/_overview/_components/accounts-selector";
import { Button, Label } from "@/components/shadcn";
import { Badge } from "@/components/shadcn/badge/badge";
import { Calendar } from "@/components/shadcn/calendar";
import { FormButtons } from "@/components/shadcn/form";
import { Input } from "@/components/shadcn/input/input";
import { Modal } from "@/components/shadcn/modal";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { toast } from "@/components/shadcn/toast";
import { trackAndPollTask } from "@/store/task-watcher/store";
import type { ProviderProps } from "@/types/providers";

import { generatePostureChangeReport } from "../_actions/posture-change-report";
import {
  defaultPostureChangePeriod,
  POSTURE_CHANGE_LANGUAGE,
  POSTURE_CHANGE_LANGUAGE_LABELS,
  type PostureChangeLanguage,
  type PostureChangePeriod,
  utcToday,
  validatePostureChangePeriod,
} from "../_lib/posture-change-period";
import { POSTURE_CHANGE_REPORT_TASK_KIND } from "../_lib/posture-change-report";

export const PostureChangeReportButton = ({
  providers,
}: {
  providers: ProviderProps[];
}) => {
  const [open, setOpen] = useState(false);

  return (
    <>
      <Button variant="outline" onClick={() => setOpen(true)}>
        <FileChartLine size={20} />
        Posture Change Report
        <Badge variant="new" size="sm">
          New
        </Badge>
      </Button>
      <Modal
        open={open}
        onOpenChange={setOpen}
        title="Generate Posture Change Report"
        description="A PDF with how findings, inventory and compliance changed for one provider between two dates (UTC)."
        size="xl"
      >
        {open && (
          <PostureChangeReportForm
            providers={providers}
            onClose={() => setOpen(false)}
          />
        )}
      </Modal>
    </>
  );
};

const PostureChangeReportForm = ({
  providers,
  onClose,
}: {
  providers: ProviderProps[];
  onClose: () => void;
}) => {
  const [providerId, setProviderId] = useState("");
  const provider = providers.find((option) => option.id === providerId);
  const providerLabel = provider
    ? provider.attributes.alias || provider.attributes.uid
    : "";
  const [today] = useState(() => utcToday(new Date()));
  const [period, setPeriod] = useState<PostureChangePeriod | undefined>(() =>
    defaultPostureChangePeriod(today),
  );
  const [reportName, setReportName] = useState("");
  const [language, setLanguage] = useState<PostureChangeLanguage>(
    POSTURE_CHANGE_LANGUAGE.EN,
  );
  const [submitting, setSubmitting] = useState(false);
  const validation = validatePostureChangePeriod(period, today);
  const periodError = "error" in validation ? validation.error : null;

  const handleSubmit = async () => {
    if ("error" in validation || !provider) return;
    setSubmitting(true);
    try {
      const result = await generatePostureChangeReport({
        providerId,
        ...validation,
        reportName: reportName.trim() || undefined,
        language,
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
        <Label htmlFor="posture-change-report-provider">Provider</Label>
        <AccountsSelector
          id="posture-change-report-provider"
          providers={providers}
          onBatchChange={(_, values) => setProviderId(values.at(-1) ?? "")}
          selectedValues={providerId ? [providerId] : []}
          closeOnSelect
          placeholder="Select a Provider"
          emptySelectionLabel="No provider selected"
          clearSelectionLabel="Clear provider selection"
        />
      </div>
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
        <Label htmlFor="posture-change-report-language">Language</Label>
        <Select
          value={language}
          onValueChange={(value) => setLanguage(value as PostureChangeLanguage)}
        >
          <SelectTrigger
            id="posture-change-report-language"
            aria-label="Report language"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {Object.values(POSTURE_CHANGE_LANGUAGE).map((value) => (
              <SelectItem key={value} value={value}>
                {POSTURE_CHANGE_LANGUAGE_LABELS[value]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
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
        isDisabled={submitting || !provider || Boolean(periodError)}
      />
    </form>
  );
};
