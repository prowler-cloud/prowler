"use client";

import { Row } from "@tanstack/react-table";
import { KeyRound, Pencil, Rocket, Trash2 } from "lucide-react";
import { useState } from "react";

import { updateOrganizationName } from "@/actions/organizations/organizations";
import { updateProvider } from "@/actions/providers";
import { VerticalDotsIcon } from "@/components/icons";
import { ProviderWizardModal } from "@/components/providers/wizard";
import {
  ORG_WIZARD_INTENT,
  OrgWizardInitialData,
} from "@/components/providers/wizard/types";
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
import { ORG_SETUP_PHASE, ORG_WIZARD_STEP } from "@/types/organizations";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";
import {
  isProvidersOrganizationRow,
  PROVIDERS_GROUP_KIND,
  PROVIDERS_ROW_TYPE,
  ProvidersOrganizationRow,
  ProvidersTableRow,
} from "@/types/providers-table";

import { DeleteForm } from "../forms/delete-form";
import { DeleteOrganizationForm } from "../forms/delete-organization-form";
import { EditNameForm } from "../forms/edit-name-form";

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

function collectTestableChildProviderIds(rows: ProvidersTableRow[]): string[] {
  const ids: string[] = [];
  for (const row of rows) {
    if (row.rowType === PROVIDERS_ROW_TYPE.PROVIDER) {
      if (row.relationships.secret.data) {
        ids.push(row.id);
      }
    } else if (row.subRows) {
      ids.push(...collectTestableChildProviderIds(row.subRows));
    }
  }
  return ids;
}

interface OrgGroupDropdownActionsProps {
  rowData: ProvidersOrganizationRow;
  loading: boolean;
  hasSelection: boolean;
  testableProviderIds: string[];
  childTestableIds: string[];
  onClearSelection: () => void;
  onBulkTest: (ids: string[]) => Promise<void>;
  onTestChildConnections: () => Promise<void>;
}

function OrgGroupDropdownActions({
  rowData,
  loading,
  hasSelection,
  testableProviderIds,
  childTestableIds,
  onClearSelection,
  onBulkTest,
  onTestChildConnections,
}: OrgGroupDropdownActionsProps) {
  const [isDeleteOrgOpen, setIsDeleteOrgOpen] = useState(false);
  const [isEditNameOpen, setIsEditNameOpen] = useState(false);
  const [isOrgWizardOpen, setIsOrgWizardOpen] = useState(false);
  const [orgWizardData, setOrgWizardData] =
    useState<OrgWizardInitialData | null>(null);

  const isOrgKind = rowData.groupKind === PROVIDERS_GROUP_KIND.ORGANIZATION;
  const testIds = hasSelection ? testableProviderIds : childTestableIds;
  const testCount = testIds.length;
  const entityLabel = isOrgKind ? "organization" : "organizational unit";

  const openOrgWizardAt = (
    targetStep: OrgWizardInitialData["targetStep"],
    targetPhase: OrgWizardInitialData["targetPhase"],
    intent?: OrgWizardInitialData["intent"],
  ) => {
    setOrgWizardData({
      organizationId: rowData.id,
      organizationName: rowData.name,
      externalId: rowData.externalId ?? "",
      targetStep,
      targetPhase,
      intent,
    });
    setIsOrgWizardOpen(true);
  };

  return (
    <>
      {isOrgKind && (
        <>
          <Modal
            open={isEditNameOpen}
            onOpenChange={setIsEditNameOpen}
            title="Edit Organization Name"
          >
            <EditNameForm
              currentValue={rowData.name}
              label="Name"
              successMessage="The organization name was updated successfully."
              helperText="If left blank, Prowler will use the name stored in AWS."
              setIsOpen={setIsEditNameOpen}
              onSave={(name) => updateOrganizationName(rowData.id, name)}
            />
          </Modal>
          <ProviderWizardModal
            open={isOrgWizardOpen}
            onOpenChange={setIsOrgWizardOpen}
            orgInitialData={orgWizardData ?? undefined}
          />
        </>
      )}
      <Modal
        open={isDeleteOrgOpen}
        onOpenChange={setIsDeleteOrgOpen}
        title="Are you absolutely sure?"
        description={`This action cannot be undone. This will permanently delete this ${entityLabel} and all associated data.`}
      >
        <DeleteOrganizationForm
          id={rowData.id}
          name={rowData.name}
          variant={rowData.groupKind}
          setIsOpen={setIsDeleteOrgOpen}
        />
      </Modal>

      <div className="relative flex items-center justify-end gap-2">
        <ActionDropdown
          trigger={
            <Button variant="ghost" size="icon-sm" className="rounded-full">
              <VerticalDotsIcon className="text-text-neutral-secondary" />
            </Button>
          }
        >
          {isOrgKind && (
            <>
              <ActionDropdownItem
                icon={<Pencil />}
                label="Edit Organization Name"
                onSelect={() => setIsEditNameOpen(true)}
              />
              <ActionDropdownItem
                icon={<KeyRound />}
                label="Update Credentials"
                onSelect={() =>
                  openOrgWizardAt(
                    ORG_WIZARD_STEP.SETUP,
                    ORG_SETUP_PHASE.ACCESS,
                    ORG_WIZARD_INTENT.EDIT_CREDENTIALS,
                  )
                }
              />
            </>
          )}
          <ActionDropdownItem
            icon={<Rocket />}
            label={loading ? "Testing..." : `Test Connections (${testCount})`}
            onSelect={(e) => {
              e.preventDefault();
              if (hasSelection) {
                onBulkTest(testableProviderIds);
                onClearSelection();
              } else {
                onTestChildConnections();
              }
            }}
            disabled={testCount === 0 || loading}
          />
          <ActionDropdownDangerZone>
            <ActionDropdownItem
              icon={<Trash2 />}
              label={
                isOrgKind ? "Delete Organization" : "Delete Organization Unit"
              }
              destructive
              onSelect={() => setIsDeleteOrgOpen(true)}
            />
          </ActionDropdownDangerZone>
        </ActionDropdown>
      </div>
    </>
  );
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

  const orgGroupKind = isOrganizationRow ? rowData.groupKind : null;
  const childTestableIds = isOrganizationRow
    ? collectTestableChildProviderIds(rowData.subRows)
    : [];

  const handleBulkTest = async (ids: string[]) => {
    if (ids.length === 0) return;
    setLoading(true);

    const results = await runWithConcurrencyLimit(ids, 10, async (id) => {
      try {
        return await testProviderConnection(id);
      } catch {
        return { connected: false, error: "Unexpected error" };
      }
    });

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
  };

  const handleTestConnection = async () => {
    if (hasSelection && isRowSelected) {
      // Bulk: test all selected providers
      await handleBulkTest(testableProviderIds);
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

  const handleTestChildConnections = async () => {
    await handleBulkTest(childTestableIds);
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
            disabled={testableProviderIds.length === 0 || loading}
          />
        </ActionDropdown>
      </div>
    );
  }

  // Organization / Organization Unit row actions
  if (isProvidersOrganizationRow(rowData) && orgGroupKind) {
    return (
      <OrgGroupDropdownActions
        rowData={rowData}
        loading={loading}
        hasSelection={hasSelection}
        testableProviderIds={testableProviderIds}
        childTestableIds={childTestableIds}
        onClearSelection={onClearSelection}
        onBulkTest={handleBulkTest}
        onTestChildConnections={handleTestChildConnections}
      />
    );
  }

  // Provider row actions (unchanged)
  return (
    <>
      <Modal
        open={isEditOpen}
        onOpenChange={setIsEditOpen}
        title="Edit Provider Alias"
      >
        {provider && (
          <EditNameForm
            currentValue={providerAlias ?? ""}
            label="Alias"
            successMessage="The provider was updated successfully."
            setIsOpen={setIsEditOpen}
            validate={(alias) => {
              if (alias !== "" && alias.length < 3) {
                return "The alias must be empty or have at least 3 characters.";
              }
              if (alias === (providerAlias ?? "")) {
                return "The new alias must be different from the current one.";
              }
              return null;
            }}
            onSave={async (alias) => {
              const formData = new FormData();
              formData.append("providerId", providerId);
              formData.append("providerAlias", alias);
              return updateProvider(formData);
            }}
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
          />
          <ActionDropdownItem
            icon={<KeyRound />}
            label="Update Credentials"
            onSelect={() => setIsWizardOpen(true)}
          />
          <ActionDropdownItem
            icon={<Rocket />}
            label={loading ? "Testing..." : "Test Connection"}
            onSelect={(e) => {
              e.preventDefault();
              handleTestConnection();
            }}
            disabled={!hasSecret || loading}
          />
          <ActionDropdownDangerZone>
            <ActionDropdownItem
              icon={<Trash2 />}
              label="Delete Provider"
              destructive
              onSelect={() => setIsDeleteOpen(true)}
            />
          </ActionDropdownDangerZone>
        </ActionDropdown>
      </div>
    </>
  );
}
