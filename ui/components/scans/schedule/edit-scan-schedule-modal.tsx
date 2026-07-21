"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { CircleX, Loader2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useForm } from "react-hook-form";

import {
  removeSchedule,
  updateSchedule,
  updateSchedulesBulk,
} from "@/actions/schedules";
import {
  ProviderTypeIconStack,
  type ProviderTypeIconStackItem,
} from "@/components/icons/providers-badge/provider-type-icon";
import { Button, FieldError } from "@/components/shadcn";
import { EntityInfo } from "@/components/shadcn/entities";
import { FormButtons } from "@/components/shadcn/form";
import { Modal } from "@/components/shadcn/modal";
import { toast } from "@/components/shadcn/toast";
import { getActionErrorMessage, hasActionError } from "@/lib/action-errors";
import { runWithConcurrencyLimit } from "@/lib/concurrency";
import {
  buildScheduleUpdatePayload,
  getScheduleFormValues,
  isScheduleConfigured,
  scheduleFormSchema,
} from "@/lib/schedules";
import type { ProviderType, ScheduleProps } from "@/types";
import type {
  ScanScheduleProvider,
  ScheduleFormValues,
} from "@/types/schedules";

import { ScanScheduleFields } from "./scan-schedule-fields";

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
  provider?: ScanScheduleProvider;
  providers?: ScanScheduleProvider[];
  providerIds?: string[];
  targetName?: string;
  targetId?: string;
  schedule: ScheduleProps | null;
  onClose: () => void;
  onSaved?: () => void;
}

interface EditScanScheduleModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  provider?: ScanScheduleProvider;
  providers?: ScanScheduleProvider[];
  providerIds?: string[];
  targetName?: string;
  targetId?: string;
  state: EditScanScheduleState;
  onSaved?: () => void;
}

function getBulkProviderTypeIconItems(
  providers: ScanScheduleProvider[],
): ProviderTypeIconStackItem[] {
  const seen = new Set<ProviderType>();
  const items: ProviderTypeIconStackItem[] = [];

  for (const provider of providers) {
    if (seen.has(provider.providerType)) continue;
    seen.add(provider.providerType);
    items.push({
      key: provider.providerType,
      type: provider.providerType,
      tooltip: provider.providerType,
    });
  }

  return items;
}

function EditScanScheduleForm({
  provider,
  providers,
  providerIds,
  targetName,
  targetId,
  schedule,
  onClose,
  onSaved,
}: EditScanScheduleFormProps) {
  const router = useRouter();
  const [isConfirmRemoveOpen, setIsConfirmRemoveOpen] = useState(false);
  const [isRemoving, setIsRemoving] = useState(false);
  const form = useForm<ScheduleFormValues>({
    resolver: zodResolver(scheduleFormSchema),
    defaultValues: getScheduleFormValues(schedule?.attributes),
  });
  const hasSchedule = schedule
    ? isScheduleConfigured(schedule.attributes)
    : false;
  const targetProviders = providers ?? (provider ? [provider] : []);
  const targetProviderIds =
    providerIds ?? targetProviders.map((target) => target.providerId);
  const referenceProvider = targetProviders[0];
  const isBulk = providers !== undefined || providerIds !== undefined;
  const bulkProviderTypeIconItems = isBulk
    ? getBulkProviderTypeIconItems(targetProviders)
    : [];
  const providerCountLabel = `${targetProviderIds.length} provider${
    targetProviderIds.length === 1 ? "" : "s"
  }`;

  const onSubmit = form.handleSubmit(async (values) => {
    const payload = buildScheduleUpdatePayload(values);
    const result = isBulk
      ? await updateSchedulesBulk(targetProviderIds, payload)
      : await updateSchedule(targetProviderIds[0], payload);

    if (hasActionError(result)) {
      form.setError("root", { message: getActionErrorMessage(result) });
      return;
    }

    toast({
      title: "Scan schedule saved",
      description: isBulk
        ? `The scan schedule was updated for ${providerCountLabel}.`
        : "The scan schedule was updated successfully.",
    });
    onSaved?.();
    onClose();
    router.refresh();
  });

  const handleRemove = async () => {
    setIsRemoving(true);
    const results = await runWithConcurrencyLimit(
      targetProviderIds,
      10,
      (providerId) => removeSchedule(providerId),
    );
    setIsRemoving(false);
    setIsConfirmRemoveOpen(false);

    const failedResult = results.find(hasActionError);
    if (failedResult) {
      form.setError("root", { message: getActionErrorMessage(failedResult) });
      return;
    }

    toast({
      title: "Scan schedule removed",
      description: isBulk
        ? `The scan schedule was removed for ${providerCountLabel}.`
        : "The scan schedule was removed successfully.",
    });
    onSaved?.();
    onClose();
    router.refresh();
  };

  const isSubmitting = form.formState.isSubmitting;
  const rootError = form.formState.errors.root?.message;

  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-8">
      {referenceProvider && (
        <EntityInfo
          cloudProvider={isBulk ? undefined : referenceProvider.providerType}
          icon={
            isBulk && bulkProviderTypeIconItems.length > 0 ? (
              <ProviderTypeIconStack
                items={bulkProviderTypeIconItems}
                max={bulkProviderTypeIconItems.length}
                size={35}
                className="flex-wrap"
              />
            ) : undefined
          }
          entityAlias={
            isBulk
              ? (targetName ?? providerCountLabel)
              : (referenceProvider.providerAlias ??
                referenceProvider.providerUid)
          }
          entityId={isBulk ? targetId : referenceProvider.providerUid}
          idLabel={isBulk ? "ID" : "UID"}
          badge={isBulk ? providerCountLabel : undefined}
        />
      )}

      <ScanScheduleFields
        form={form}
        disabled={isSubmitting || isRemoving}
        headerAction={
          hasSchedule ? (
            <Button
              type="button"
              variant="ghost"
              onClick={() => setIsConfirmRemoveOpen(true)}
              disabled={isSubmitting || isRemoving}
              className="text-text-error-primary"
            >
              <CircleX className="size-4" />
              Remove Scan Schedule
            </Button>
          ) : undefined
        }
      />

      {rootError && <FieldError>{rootError}</FieldError>}

      <FormButtons
        onCancel={onClose}
        submitText={isSubmitting ? "Saving..." : "Save"}
        loadingText="Saving..."
        isDisabled={isSubmitting || isRemoving}
      />

      <Modal
        open={isConfirmRemoveOpen}
        onOpenChange={setIsConfirmRemoveOpen}
        title="Are you absolutely sure?"
        description={
          isBulk
            ? `This action cannot be undone. The scan schedule for these ${providerCountLabel} will be removed and scans will no longer run automatically.`
            : "This action cannot be undone. The scan schedule for this provider will be removed and scans will no longer run automatically."
        }
      >
        <div className="flex w-full justify-end gap-4">
          <Button
            type="button"
            variant="ghost"
            size="lg"
            onClick={() => setIsConfirmRemoveOpen(false)}
            disabled={isRemoving}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="destructive"
            size="lg"
            onClick={() => void handleRemove()}
            disabled={isRemoving}
          >
            <CircleX className="size-4" />
            {isRemoving ? "Removing..." : "Remove"}
          </Button>
        </div>
      </Modal>
    </form>
  );
}

export function EditScanScheduleModal({
  open,
  onOpenChange,
  provider,
  providers,
  providerIds,
  targetName,
  targetId,
  state,
  onSaved,
}: EditScanScheduleModalProps) {
  const close = () => onOpenChange(false);
  const hasTarget = Boolean(
    provider || providers?.length || providerIds?.length,
  );
  const keyPrefix =
    provider?.providerId ??
    providerIds?.join(":") ??
    providers?.map((item) => item.providerId).join(":");

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

      {state.kind === EDIT_SCAN_SCHEDULE_STATE.LOADED && hasTarget && (
        <EditScanScheduleForm
          key={`${keyPrefix}-${state.schedule?.attributes.scan_hour ?? "none"}`}
          provider={provider}
          providers={providers}
          providerIds={providerIds}
          targetName={targetName}
          targetId={targetId}
          schedule={state.schedule}
          onClose={close}
          onSaved={onSaved}
        />
      )}
    </Modal>
  );
}
