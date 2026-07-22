"use client";

import { ChevronDownIcon, DownloadIcon, FileTextIcon } from "lucide-react";
import { useState } from "react";

import { Button, Label } from "@/components/shadcn";
import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { FormButtons } from "@/components/shadcn/form";
import { Input } from "@/components/shadcn/input/input";
import { Modal } from "@/components/shadcn/modal";
import { toast } from "@/components/shadcn/toast";
import {
  TASK_WATCHER_STATUS,
  trackAndPollTask,
  useTaskWatcherStore,
} from "@/store/task-watcher/store";

import { generateCrossAccountPdf } from "../_actions/cross-account";
import { generateCrossProviderPdf } from "../_actions/cross-provider";
import {
  buildCrossAccountPdfTaskScope,
  CROSS_ACCOUNT_PDF_TASK_KIND,
  downloadCrossAccountPdf,
} from "../_lib/cross-account-pdf";
import {
  buildCrossProviderPdfTaskScope,
  CROSS_PROVIDER_PDF_TASK_KIND,
  downloadCrossProviderPdf,
} from "../_lib/cross-provider-pdf";
import type {
  CrossProviderApiFilters,
  LatestCrossProviderPdf,
} from "../_types";

interface CrossProviderPdfButtonProps {
  complianceId: string;
  /** Set to switch the button to cross-account mode: same UI, but the
   *  generate/download/latest plumbing targets the cross-account endpoints
   *  and task kind for this provider type's accounts. */
  providerType?: string;
  /** The filters (and exact scan ids) of the view currently on screen, so
   *  the generated PDF matches what the user is looking at. */
  filters: CrossProviderApiFilters;
  /** Already-generated report matching these filters, if any — offered as an
   *  instant download instead of forcing a re-generate. */
  latestPdf: LatestCrossProviderPdf | null;
}

export const CrossProviderPdfButton = ({
  complianceId,
  providerType,
  filters,
  latestPdf,
}: CrossProviderPdfButtonProps) => {
  const [dialogOpen, setDialogOpen] = useState(false);
  const [reportName, setReportName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const isCrossAccount = providerType !== undefined;
  const taskKind = isCrossAccount
    ? CROSS_ACCOUNT_PDF_TASK_KIND
    : CROSS_PROVIDER_PDF_TASK_KIND;
  const downloadPdf = isCrossAccount
    ? downloadCrossAccountPdf
    : downloadCrossProviderPdf;
  const taskScope = isCrossAccount
    ? buildCrossAccountPdfTaskScope(complianceId, providerType, filters)
    : buildCrossProviderPdfTaskScope(complianceId, filters);

  const isGenerating = useTaskWatcherStore((state) =>
    Object.values(state.tasks).some(
      (task) =>
        task.kind === taskKind &&
        task.status === TASK_WATCHER_STATUS.PENDING &&
        task.meta.scopeKey === taskScope,
    ),
  );
  const completedTask = useTaskWatcherStore((state) =>
    Object.values(state.tasks).reduce<(typeof state.tasks)[string] | undefined>(
      (latest, task) => {
        if (
          task.kind !== taskKind ||
          task.status !== TASK_WATCHER_STATUS.READY ||
          task.meta.scopeKey !== taskScope
        ) {
          return latest;
        }

        return !latest || task.startedAt > latest.startedAt ? task : latest;
      },
      undefined,
    ),
  );
  const availablePdf: LatestCrossProviderPdf | null = completedTask
    ? {
        taskId: completedTask.taskId,
        filename: completedTask.meta.reportLabel,
      }
    : latestPdf;

  const handleGenerate = async () => {
    setSubmitting(true);
    try {
      const result = isCrossAccount
        ? await generateCrossAccountPdf({
            complianceId,
            providerType,
            filters,
            reportName: reportName.trim() || undefined,
          })
        : await generateCrossProviderPdf({
            complianceId,
            filters,
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

      setDialogOpen(false);
      toast({
        title: "Report generation started",
        description:
          "We'll let you know when the PDF is ready — you can keep working meanwhile.",
      });
      await trackAndPollTask({
        taskId: result.taskId,
        kind: taskKind,
        meta: {
          complianceId,
          scopeKey: taskScope,
          ...(reportName.trim() ? { reportLabel: reportName.trim() } : {}),
        },
      });
    } catch {
      // The action returns {error} for API failures; this guards the
      // server-action RPC itself (e.g. a network drop mid-request).
      toast({
        variant: "destructive",
        title: "Could not start report generation",
        description: "An unexpected error occurred. Please try again later.",
      });
    } finally {
      setSubmitting(false);
    }
  };

  const formatGeneratedAt = (completedAt?: string) => {
    if (!completedAt) return "";
    const date = new Date(completedAt);
    return Number.isNaN(date.getTime())
      ? ""
      : ` (${date.toLocaleDateString()})`;
  };

  return (
    <>
      {/* Same trigger as the per-scan detail's export dropdown, so both
          compliance headers expose one consistent "Report" action. */}
      {isGenerating ? (
        <Button variant="outline" disabled>
          Generating report…
        </Button>
      ) : (
        <ActionDropdown
          variant="bordered"
          ariaLabel="Compliance report actions"
          trigger={
            <Button variant="outline">
              Report
              <ChevronDownIcon />
            </Button>
          }
        >
          {availablePdf && (
            <ActionDropdownItem
              icon={<DownloadIcon />}
              label={`Download latest${formatGeneratedAt(availablePdf.completedAt)}`}
              description={availablePdf.filename}
              onSelect={() => downloadPdf(availablePdf.taskId)}
            />
          )}
          <ActionDropdownItem
            icon={<FileTextIcon />}
            label="Generate new report…"
            onSelect={() => setDialogOpen(true)}
          />
        </ActionDropdown>
      )}

      <Modal
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        title={
          isCrossAccount
            ? "Generate Cross-Account Report"
            : "Generate Cross-Provider Report"
        }
        description={
          isCrossAccount
            ? "The report covers the accounts and filters currently applied to this view."
            : "The report covers the providers, accounts and filters currently applied to this view."
        }
        size="xl"
      >
        <form
          onSubmit={(event) => {
            event.preventDefault();
            handleGenerate();
          }}
          className="flex flex-col gap-6"
        >
          <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-2">
              <Label htmlFor="cross-provider-report-name">Report name</Label>
              <Input
                id="cross-provider-report-name"
                placeholder="Optional — a timestamped name is used by default"
                value={reportName}
                onChange={(event) => setReportName(event.target.value)}
              />
            </div>
          </div>

          <FormButtons
            onCancel={() => setDialogOpen(false)}
            submitText="Generate"
            loadingText="Starting..."
            isDisabled={submitting}
          />
        </form>
      </Modal>
    </>
  );
};
