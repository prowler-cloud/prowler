"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { CircleX, Loader2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";

import { removeSchedule, updateSchedule } from "@/actions/schedules";
import { Button, FieldError } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { EntityInfo } from "@/components/ui/entities";
import { FormButtons } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";
import {
  buildScheduleUpdatePayload,
  getScheduleFormValues,
  isScheduleConfigured,
  scheduleFormSchema,
} from "@/lib/schedules";
import type { ProviderType, ScheduleProps } from "@/types";
import type { ScheduleFormValues } from "@/types/schedules";

import { ScanScheduleFields } from "./scan-schedule-fields";

export interface ScanScheduleProvider {
  providerId: string;
  providerType: ProviderType;
  providerUid: string;
  providerAlias: string | null;
}

export const EDIT_SCAN_SCHEDULE_STATE = {
  LOADING: "loading",
  LOADED: "loaded",
  ERROR: "error",
} as const;

export type EditScanScheduleState =
  | { kind: typeof EDIT_SCAN_SCHEDULE_STATE.LOADING }
  | {
      kind: typeof EDIT_SCAN_SCHEDULE_STATE.LOADED;
      schedule: ScheduleProps | null;
    }
  | { kind: typeof EDIT_SCAN_SCHEDULE_STATE.ERROR; message: string };

interface EditScanScheduleFormProps {
  provider: ScanScheduleProvider;
  schedule: ScheduleProps | null;
  onClose: () => void;
}

interface EditScanScheduleModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  provider?: ScanScheduleProvider;
  state: EditScanScheduleState;
}

function EditScanScheduleForm({
  provider,
  schedule,
  onClose,
}: EditScanScheduleFormProps) {
  const router = useRouter();
  const form = useForm<ScheduleFormValues>({
    resolver: zodResolver(scheduleFormSchema),
    defaultValues: getScheduleFormValues(schedule?.attributes),
  });
  const hasSchedule = schedule
    ? isScheduleConfigured(schedule.attributes)
    : false;

  const onSubmit = form.handleSubmit(async (values) => {
    const result = await updateSchedule(
      provider.providerId,
      buildScheduleUpdatePayload(values),
    );

    if (result?.error) {
      form.setError("root", { message: String(result.error) });
      return;
    }

    toast({
      title: "Scan schedule saved",
      description: "The scan schedule was updated successfully.",
    });
    onClose();
    router.refresh();
  });

  const handleRemove = async () => {
    const result = await removeSchedule(provider.providerId);

    if (result?.error) {
      form.setError("root", { message: String(result.error) });
      return;
    }

    toast({
      title: "Scan schedule removed",
      description: "The scan schedule was removed successfully.",
    });
    onClose();
    router.refresh();
  };

  const isSubmitting = form.formState.isSubmitting;
  const rootError = form.formState.errors.root?.message;

  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-8">
      <EntityInfo
        cloudProvider={provider.providerType}
        entityAlias={provider.providerAlias ?? provider.providerUid}
        entityId={provider.providerUid}
      />

      <div className="flex flex-col gap-4">
        <div className="flex items-center justify-between gap-4">
          <span className="sr-only">Schedule actions</span>
          {hasSchedule && (
            <Button
              type="button"
              variant="ghost"
              onClick={() => void handleRemove()}
              disabled={isSubmitting}
              className="text-text-error-primary ml-auto"
            >
              <CircleX className="size-4" />
              Remove Scan Schedule
            </Button>
          )}
        </div>
        <ScanScheduleFields form={form} disabled={isSubmitting} />
      </div>

      {rootError && <FieldError>{rootError}</FieldError>}

      <FormButtons
        onCancel={onClose}
        submitText={isSubmitting ? "Saving..." : "Save"}
        loadingText="Saving..."
        isDisabled={isSubmitting}
      />
    </form>
  );
}

export function EditScanScheduleModal({
  open,
  onOpenChange,
  provider,
  state,
}: EditScanScheduleModalProps) {
  const close = () => onOpenChange(false);

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Edit Scan Schedule"
      size="2xl"
      className="gap-8"
    >
      {state.kind === EDIT_SCAN_SCHEDULE_STATE.LOADING && (
        <div className="flex min-h-[240px] items-center justify-center gap-3">
          <Loader2 className="size-5 animate-spin" />
          <span className="text-sm">Loading scan schedule...</span>
        </div>
      )}

      {state.kind === EDIT_SCAN_SCHEDULE_STATE.ERROR && (
        <div className="flex flex-col gap-6">
          <FieldError>{state.message}</FieldError>
          <Button type="button" variant="outline" onClick={close}>
            Close
          </Button>
        </div>
      )}

      {state.kind === EDIT_SCAN_SCHEDULE_STATE.LOADED && provider && (
        <EditScanScheduleForm
          key={`${provider.providerId}-${state.schedule?.attributes.scan_hour ?? "none"}`}
          provider={provider}
          schedule={state.schedule}
          onClose={close}
        />
      )}
    </Modal>
  );
}
