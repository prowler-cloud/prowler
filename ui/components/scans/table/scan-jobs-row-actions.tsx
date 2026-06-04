"use client";

import {
  CalendarClock,
  Download,
  Eye,
  Pencil,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { getSchedule } from "@/actions/schedules";
import { getTask } from "@/actions/task";
import { getScanErrorDetails } from "@/actions/task/task.adapter";
import { EditAliasModal } from "@/components/scans/edit-alias-modal";
import {
  ScanErrorDetailsModal,
  type ScanErrorDetailsState,
} from "@/components/scans/scan-error-details-modal";
import {
  EDIT_SCAN_SCHEDULE_STATE,
  EditScanScheduleModal,
  type EditScanScheduleState,
  type ScanScheduleProvider,
} from "@/components/scans/schedule/edit-scan-schedule-modal";
import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { useToast } from "@/components/ui";
import { toLocalDateString } from "@/lib/date-utils";
import { downloadScanZip } from "@/lib/helper";
import type { ProviderType, ScanProps, ScheduleApiResponse } from "@/types";

interface ScanJobsRowActionsProps {
  scan: ScanProps;
}

export function ScanJobsRowActions({ scan }: ScanJobsRowActionsProps) {
  const router = useRouter();
  const { toast } = useToast();
  const [editOpen, setEditOpen] = useState(false);
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const [scheduleState, setScheduleState] = useState<EditScanScheduleState>({
    kind: EDIT_SCAN_SCHEDULE_STATE.LOADING,
  });
  const [errorOpen, setErrorOpen] = useState(false);
  const [errorState, setErrorState] = useState<ScanErrorDetailsState>({
    kind: "idle",
  });
  const scanState = scan.attributes.state;
  const isCompleted = scanState === "completed";
  const isFailed = scanState === "failed";
  const taskId = scan.relationships.task.data?.id;
  const scanDate = toLocalDateString(scan.attributes.completed_at);
  const providerId = scan.relationships.provider.data?.id;
  const scheduleProvider: ScanScheduleProvider | undefined = providerId
    ? {
        providerId,
        providerType: (scan.providerInfo?.provider ?? "aws") as ProviderType,
        providerUid: scan.providerInfo?.uid ?? providerId,
        providerAlias: scan.providerInfo?.alias ?? null,
      }
    : undefined;

  const openFindings = () => {
    if (!isCompleted || !scanDate) return;
    router.push(
      `/findings?filter[scan]=${scan.id}&filter[inserted_at]=${scanDate}&filter[status__in]=FAIL`,
    );
  };

  const openCompliance = () => {
    if (!isCompleted) return;
    router.push(`/compliance?scanId=${scan.id}`);
  };

  const openErrorDetails = async () => {
    setErrorOpen(true);
    setErrorState({ kind: "loading" });

    if (!taskId) {
      setErrorState({
        kind: "error",
        message: "Task ID is not available for this scan.",
      });
      return;
    }

    const response: unknown = await getTask(taskId);

    if (
      typeof response === "object" &&
      response !== null &&
      "error" in response &&
      typeof (response as { error: unknown }).error === "string"
    ) {
      setErrorState({
        kind: "error",
        message: (response as { error: string }).error,
      });
      return;
    }

    const details = getScanErrorDetails(response);

    if (!details) {
      setErrorState({
        kind: "error",
        message: "No error details were found for this failed scan.",
      });
      return;
    }

    setErrorState({ kind: "loaded", details });
  };

  const openScheduleEditor = async () => {
    if (!providerId) {
      setScheduleState({
        kind: EDIT_SCAN_SCHEDULE_STATE.ERROR,
        message: "Provider ID is not available for this scan.",
      });
      setScheduleOpen(true);
      return;
    }

    setScheduleState({ kind: EDIT_SCAN_SCHEDULE_STATE.LOADING });
    setScheduleOpen(true);

    const response = (await getSchedule(providerId)) as
      | ScheduleApiResponse
      | { error?: string };

    if (!response || ("error" in response && response.error)) {
      setScheduleState({
        kind: EDIT_SCAN_SCHEDULE_STATE.ERROR,
        message:
          response && "error" in response && response.error
            ? response.error
            : "Failed to load scan schedule.",
      });
      return;
    }

    setScheduleState({
      kind: EDIT_SCAN_SCHEDULE_STATE.LOADED,
      schedule: "data" in response ? response.data : null,
    });
  };

  return (
    <div className="flex items-center justify-end">
      <ActionDropdown>
        {isCompleted && (
          <>
            <ActionDropdownItem
              icon={<Eye />}
              label="View Findings"
              onSelect={openFindings}
              disabled={!isCompleted || !scanDate}
            />
            <ActionDropdownItem
              icon={<ShieldCheck />}
              label="View Compliance"
              onSelect={openCompliance}
            />
            <ActionDropdownItem
              icon={<Download />}
              label="Download Scan Reports"
              onSelect={() => downloadScanZip(scan.id, toast)}
            />
          </>
        )}
        {isFailed && (
          <ActionDropdownItem
            icon={<TriangleAlert />}
            label="View error details"
            onSelect={() => void openErrorDetails()}
          />
        )}
        {/* TODO: Expand Edit to also cover schedule once the backend exposes a schedule update endpoint. */}
        <ActionDropdownItem
          icon={<Pencil />}
          label="Edit"
          onSelect={() => setEditOpen(true)}
        />
        <ActionDropdownItem
          icon={<CalendarClock />}
          label="Edit Scan Schedule"
          onSelect={() => void openScheduleEditor()}
        />
        {/* TODO: Restore Cancel Scan once the backend exposes a public scan cancellation endpoint. */}
      </ActionDropdown>

      <EditAliasModal
        open={editOpen}
        onOpenChange={setEditOpen}
        scanId={scan.id}
        currentAlias={scan.attributes.name ?? ""}
      />

      <ScanErrorDetailsModal
        open={errorOpen}
        onOpenChange={setErrorOpen}
        state={errorState}
      />

      <EditScanScheduleModal
        open={scheduleOpen}
        onOpenChange={setScheduleOpen}
        provider={scheduleProvider}
        state={scheduleState}
      />
    </div>
  );
}
