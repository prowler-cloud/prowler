"use client";

import { Row } from "@tanstack/react-table";
import { KeyRound, Pencil, Rocket, Trash2 } from "lucide-react";
import { useState } from "react";

import { VerticalDotsIcon } from "@/components/icons";
import { ProviderWizardModal } from "@/components/providers/wizard";
import { Button } from "@/components/shadcn";
import {
  ActionDropdown,
  ActionDropdownDangerZone,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/ui";
import { runWithConcurrencyLimit } from "@/lib/concurrency";
import { testProviderConnection } from "@/lib/provider-helpers";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";
import {
  isProvidersOrganizationRow,
  ProvidersTableRow,
} from "@/types/providers-table";

import { EditForm } from "../forms";
import { DeleteForm } from "../forms/delete-form";

interface DataTableRowActionsProps {
  row: Row<ProvidersTableRow>;
  /** Whether any rows in the table are currently selected */
  hasSelection: boolean;
  /** Whether this specific row is selected */
  isRowSelected: boolean;
  /** IDs of all selected providers that have credentials (testable) */
  testableProviderIds: string[];
  /** Callback to clear the row selection after bulk operation */
  onClearSelection: () => void;
}

export function DataTableRowActions({
  row,
  hasSelection,
  isRowSelected,
  testableProviderIds,
  onClearSelection,
}: DataTableRowActionsProps) {
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const [isWizardOpen, setIsWizardOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  const rowData = row.original;
  const isOrganizationRow = isProvidersOrganizationRow(rowData);
  const provider = isOrganizationRow ? null : rowData;
  const providerId = provider?.id ?? "";
  const providerType = provider?.attributes.provider ?? "aws";
  const providerUid = provider?.attributes.uid ?? "";
  const providerAlias = provider?.attributes.alias ?? null;
  const providerSecretId = provider?.relationships.secret.data?.id ?? null;
  const hasSecret = Boolean(provider?.relationships.secret.data);

  const handleTestConnection = async () => {
    if (hasSelection && isRowSelected) {
      // Bulk: test all selected providers
      if (testableProviderIds.length === 0) return;
      setLoading(true);

      const results = await runWithConcurrencyLimit(
        testableProviderIds,
        10,
        async (id) => {
          try {
            return await testProviderConnection(id);
          } catch {
            return { connected: false, error: "Unexpected error" };
          }
        },
      );

      const succeeded = results.filter((r) => r.connected).length;
      const failed = results.length - succeeded;

      if (failed === 0) {
        toast({
          title: "Connection test completed",
          description: `${succeeded} ${succeeded === 1 ? "provider" : "providers"} tested successfully.`,
        });
      } else {
        toast({
          variant: "destructive",
          title: "Connection test completed",
          description: `${succeeded} succeeded, ${failed} failed out of ${results.length} providers.`,
        });
      }

      setLoading(false);
      onClearSelection();
    } else {
      // Single: test only this provider
      if (!providerId) return;
      setLoading(true);
      const result = await testProviderConnection(providerId);
      setLoading(false);

      if (!result.connected) {
        toast({
          variant: "destructive",
          title: "Connection test failed",
          description: result.error ?? "Unknown error",
        });
      } else {
        toast({
          title: "Connection test completed",
          description: "Provider tested successfully.",
        });
      }
    }
  };

  // When this row is part of the selection, only show "Test Connection"
  if (hasSelection && isRowSelected) {
    const bulkCount =
      testableProviderIds.length > 1 ? ` (${testableProviderIds.length})` : "";

    return (
      <div className="relative flex items-center justify-end gap-2">
        <ActionDropdown
          trigger={
            <Button variant="ghost" size="icon-sm" className="rounded-full">
              <VerticalDotsIcon className="text-text-neutral-secondary" />
            </Button>
          }
        >
          <ActionDropdownItem
            icon={<Rocket />}
            label={loading ? "Testing..." : `Test Connection${bulkCount}`}
            onSelect={(e) => {
              e.preventDefault();
              handleTestConnection();
            }}
            disabled={
              isOrganizationRow || testableProviderIds.length === 0 || loading
            }
          />
        </ActionDropdown>
      </div>
    );
  }

  // Normal mode: all actions
  return (
    <>
      <Modal
        open={isEditOpen}
        onOpenChange={setIsEditOpen}
        title="Edit Provider Alias"
      >
        {provider && (
          <EditForm
            providerId={providerId}
            providerAlias={providerAlias ?? undefined}
            setIsOpen={setIsEditOpen}
          />
        )}
      </Modal>
      <Modal
        open={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Are you absolutely sure?"
        description="This action cannot be undone. This will permanently delete your provider account and remove your data from the server."
      >
        {provider && (
          <DeleteForm providerId={providerId} setIsOpen={setIsDeleteOpen} />
        )}
      </Modal>
      <ProviderWizardModal
        open={isWizardOpen}
        onOpenChange={setIsWizardOpen}
        initialData={{
          providerId,
          providerType,
          providerUid,
          providerAlias,
          secretId: providerSecretId,
          mode: providerSecretId
            ? PROVIDER_WIZARD_MODE.UPDATE
            : PROVIDER_WIZARD_MODE.ADD,
        }}
      />

      <div className="relative flex items-center justify-end gap-2">
        <ActionDropdown
          trigger={
            <Button variant="ghost" size="icon-sm" className="rounded-full">
              <VerticalDotsIcon className="text-text-neutral-secondary" />
            </Button>
          }
        >
          <ActionDropdownItem
            icon={<Pencil />}
            label="Edit Provider Alias"
            onSelect={() => setIsEditOpen(true)}
            disabled={isOrganizationRow}
          />
          <ActionDropdownItem
            icon={<KeyRound />}
            label="Update Credentials"
            onSelect={() => setIsWizardOpen(true)}
            disabled={isOrganizationRow}
          />
          <ActionDropdownItem
            icon={<Rocket />}
            label={loading ? "Testing..." : "Test Connection"}
            onSelect={(e) => {
              e.preventDefault();
              handleTestConnection();
            }}
            disabled={isOrganizationRow || !hasSecret || loading}
          />
          <ActionDropdownDangerZone>
            <ActionDropdownItem
              icon={<Trash2 />}
              label="Delete Provider"
              destructive
              onSelect={() => setIsDeleteOpen(true)}
              disabled={isOrganizationRow}
            />
          </ActionDropdownDangerZone>
        </ActionDropdown>
      </div>
    </>
  );
}
