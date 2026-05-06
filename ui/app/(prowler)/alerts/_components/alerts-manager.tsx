"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import {
  deleteAlert,
  disableAlert,
  enableAlert,
  updateAlert,
} from "@/app/(prowler)/alerts/_actions";
import {
  ALERT_TRIGGER_KINDS,
  type AlertRule,
} from "@/app/(prowler)/alerts/_types";
import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/ui";
import type { MetaDataProps } from "@/types";
import type { ScanEntity } from "@/types";
import type { ProviderProps } from "@/types/providers";

import { toAlertPayload } from "../_lib/alert-adapter";
import type {
  AlertFormSubmitResult,
  AlertFormValues,
} from "../_types/alert-form";
import { AlertFormModal } from "./alert-form-modal";
import { AlertsEmptyState } from "./alerts-empty-state";
import { AlertsTable } from "./alerts-table";

interface AlertsManagerProps {
  alerts: AlertRule[];
  meta?: MetaDataProps;
  loadError: string | null;
  providers: ProviderProps[];
  completedScanIds: string[];
  scanDetails: { [key: string]: ScanEntity }[];
  uniqueRegions: string[];
  uniqueServices: string[];
  uniqueResourceTypes: string[];
  uniqueCategories: string[];
  uniqueGroups: string[];
  initialEditingAlert?: AlertRule | null;
}

export const AlertsManager = ({
  alerts,
  meta,
  loadError,
  providers,
  completedScanIds,
  scanDetails,
  uniqueRegions,
  uniqueServices,
  uniqueResourceTypes,
  uniqueCategories,
  uniqueGroups,
  initialEditingAlert = null,
}: AlertsManagerProps) => {
  const router = useRouter();
  const { toast } = useToast();
  const [, startTransition] = useTransition();
  const [modalOpen, setModalOpen] = useState(Boolean(initialEditingAlert));
  const [editingAlert, setEditingRule] = useState<AlertRule | null>(
    initialEditingAlert,
  );
  const [mutatingId, setMutatingId] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<AlertRule | null>(null);

  const refresh = () => startTransition(() => router.refresh());

  const closeModal = (open: boolean) => {
    setModalOpen(open);
    if (!open) {
      setEditingRule(null);
      router.replace("/alerts");
    }
  };

  const submitAlert = async (
    values: AlertFormValues,
  ): Promise<AlertFormSubmitResult> => {
    if (!editingAlert) {
      return { ok: false, error: "Create alerts from Findings." };
    }
    const payload = toAlertPayload(values);
    const result = await updateAlert(editingAlert.id, payload);
    if (!result.ok) return { ok: false, error: result.error.detail };
    toast({
      title: "Alert updated",
      description: result.data.data.attributes.name,
    });
    refresh();
    return { ok: true, alertId: result.data.data.id };
  };

  const toggleAlert = async (alert: AlertRule) => {
    setMutatingId(alert.id);
    const result = alert.attributes.enabled
      ? await disableAlert(alert.id)
      : await enableAlert(alert.id);
    setMutatingId(null);
    if (!result.ok) {
      toast({
        variant: "destructive",
        title: "Alert update failed",
        description: result.error.detail,
      });
      return;
    }
    toast({
      title: alert.attributes.enabled ? "Alert disabled" : "Alert enabled",
      description: result.data.data.attributes.name,
    });
    refresh();
  };

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    setMutatingId(pendingDelete.id);
    const result = await deleteAlert(pendingDelete.id);
    setMutatingId(null);
    if (!result.ok) {
      toast({
        variant: "destructive",
        title: "Alert delete failed",
        description: result.error.detail,
      });
      return;
    }
    setPendingDelete(null);
    refresh();
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="flex max-w-3xl flex-col gap-2">
          <h1 className="text-text-neutral-primary text-2xl font-semibold">
            Alerts
          </h1>
          <p className="text-text-neutral-secondary text-sm">
            Manage alerts for finding conditions.
          </p>
        </div>
      </div>

      {loadError && (
        <div className="border-destructive/40 bg-destructive/10 text-destructive rounded-md border p-4 text-sm">
          Failed to load alerts: {loadError}
        </div>
      )}

      {alerts.length === 0 && !loadError ? (
        <AlertsEmptyState />
      ) : (
        <AlertsTable
          alerts={alerts}
          meta={meta}
          mutatingId={mutatingId}
          onEdit={(alert) => {
            setEditingRule(alert);
            setModalOpen(true);
          }}
          onToggleEnabled={toggleAlert}
          onDelete={setPendingDelete}
        />
      )}

      <AlertFormModal
        key={editingAlert?.id ?? "edit"}
        open={modalOpen}
        defaultFrequency={ALERT_TRIGGER_KINDS.AFTER_SCAN}
        providers={providers}
        completedScanIds={completedScanIds}
        scanDetails={scanDetails}
        uniqueRegions={uniqueRegions}
        uniqueServices={uniqueServices}
        uniqueResourceTypes={uniqueResourceTypes}
        uniqueCategories={uniqueCategories}
        uniqueGroups={uniqueGroups}
        editingAlert={editingAlert}
        onOpenChange={closeModal}
        onSubmit={submitAlert}
      />

      <Modal
        open={Boolean(pendingDelete)}
        onOpenChange={(open) => !open && setPendingDelete(null)}
        title="Delete alert"
        description={
          pendingDelete
            ? `Delete "${pendingDelete.attributes.name}"? This alert will stop evaluating.`
            : ""
        }
        size="md"
      >
        <div className="flex justify-end gap-2 pt-4">
          <Button variant="outline" onClick={() => setPendingDelete(null)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            disabled={mutatingId === pendingDelete?.id}
            onClick={confirmDelete}
          >
            Delete alert
          </Button>
        </div>
      </Modal>
    </div>
  );
};
