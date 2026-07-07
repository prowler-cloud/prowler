"use client";

import { Row } from "@tanstack/react-table";
import {
  CalendarClock,
  KeyRound,
  Pencil,
  Rocket,
  SlidersHorizontal,
  Timer,
  Trash2,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { updateOrganizationName } from "@/actions/organizations/organizations";
import { updateProvider } from "@/actions/providers";
import { getSchedule } from "@/actions/schedules";
import {
  ORG_WIZARD_INTENT,
  OrgWizardInitialData,
  ProviderWizardInitialData,
} from "@/components/providers/wizard/types";
import {
  EDIT_SCAN_SCHEDULE_STATE,
  EditScanScheduleModal,
  type EditScanScheduleState,
} from "@/components/scans/schedule/edit-scan-schedule-modal";
import { useToast } from "@/components/shadcn";
import {
  ActionDropdown,
  ActionDropdownDangerZone,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { Modal } from "@/components/shadcn/modal";
import { runWithConcurrencyLimit } from "@/lib/concurrency";
import { testProviderConnection } from "@/lib/provider-helpers";
import { getScanScheduleCapability } from "@/lib/schedules";
import { isCloud } from "@/lib/shared/env";
import { ORG_SETUP_PHASE, ORG_WIZARD_STEP } from "@/types/organizations";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";
import {
  isProvidersOrganizationRow,
  PROVIDERS_GROUP_KIND,
  PROVIDERS_ROW_TYPE,
  ProvidersOrganizationRow,
  ProvidersTableRow,
} from "@/types/providers-table";
import {
  SCAN_CONFIGURATION_LIST_STATUS,
  ScanConfigurationData,
  type ScanConfigurationListStatus,
} from "@/types/scan-configurations";
import {
  SCAN_SCHEDULE_CAPABILITY,
  type ScanScheduleCapability,
  type ScanScheduleProvider,
  type ScheduleApiResponse,
} from "@/types/schedules";

import { DeleteForm } from "../forms/delete-form";
import { DeleteOrganizationForm } from "../forms/delete-organization-form";
import { EditNameForm } from "../forms/edit-name-form";
import { ManageScanConfigModal } from "../scan-config/manage-scan-config-modal";

interface DataTableRowActionsProps {
  row: Row<ProvidersTableRow>;
  /** Whether any rows in the table are currently selected */
  hasSelection: boolean;
  /** Whether this specific row is selected */
  isRowSelected: boolean;
  /** IDs of all selected providers that have credentials (testable) */
  testableProviderIds: string[];
  /** IDs of all selected providers that can receive schedule updates. */
  selectedScheduleProviderIds?: string[];
  /** Visible selected providers used as modal reference rows. */
  selectedScheduleProviders?: ScanScheduleProvider[];
  /** Callback to clear the row selection after bulk operation */
  onClearSelection: () => void;
  onOpenProviderWizard: (initialData?: ProviderWizardInitialData) => void;
  onOpenOrganizationWizard: (initialData: OrgWizardInitialData) => void;
  /**
   * All scan configurations in the tenant, used to associate/disassociate this
   * provider's config from the row menu (Cloud-only feature). Empty in OSS.
   */
  scanConfigs?: ScanConfigurationData[];
  scanConfigStatus?: ScanConfigurationListStatus;
  currentScanConfigId?: string | null;
  /**
   * Schedule capability override. Absent in OSS (defaults to a Cloud-vs-non-Cloud
   * decision). The prowler-cloud overlay injects a billing-aware capability so
   * only subscribed Cloud accounts can open the advanced schedule editor (which
   * talks to the new schedule API).
   */
  capability?: ScanScheduleCapability;
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

function collectChildScheduleProviders(
  rows: ProvidersTableRow[],
): ScanScheduleProvider[] {
  const providers: ScanScheduleProvider[] = [];

  for (const row of rows) {
    if (row.rowType === PROVIDERS_ROW_TYPE.PROVIDER) {
      providers.push({
        providerId: row.id,
        providerType: row.attributes.provider,
        providerUid: row.attributes.uid,
        providerAlias: row.attributes.alias,
      });
      continue;
    }

    providers.push(...collectChildScheduleProviders(row.subRows));
  }

  return providers;
}

interface OrgGroupDropdownActionsProps {
  rowData: ProvidersOrganizationRow;
  loading: boolean;
  canEditSchedule: boolean;
  hasSelection: boolean;
  testableProviderIds: string[];
  childTestableIds: string[];
  scheduleProviderCount: number;
  onClearSelection: () => void;
  onBulkTest: (ids: string[]) => Promise<void>;
  onTestChildConnections: () => Promise<void>;
  onOpenOrganizationWizard: (initialData: OrgWizardInitialData) => void;
  onOpenScheduleEditor: () => void;
}

function OrgGroupDropdownActions({
  rowData,
  loading,
  canEditSchedule,
  hasSelection,
  testableProviderIds,
  childTestableIds,
  scheduleProviderCount,
  onClearSelection,
  onBulkTest,
  onTestChildConnections,
  onOpenOrganizationWizard,
  onOpenScheduleEditor,
}: OrgGroupDropdownActionsProps) {
  const [isDeleteOrgOpen, setIsDeleteOrgOpen] = useState(false);
  const [isEditNameOpen, setIsEditNameOpen] = useState(false);

  const isOrgKind = rowData.groupKind === PROVIDERS_GROUP_KIND.ORGANIZATION;
  const testIds = hasSelection ? testableProviderIds : childTestableIds;
  const testCount = testIds.length;
  const entityLabel = isOrgKind ? "organization" : "organizational unit";

  const openOrgWizardAt = (
    targetStep: OrgWizardInitialData["targetStep"],
    targetPhase: OrgWizardInitialData["targetPhase"],
    intent?: OrgWizardInitialData["intent"],
  ) => {
    onOpenOrganizationWizard({
      organizationId: rowData.id,
      organizationName: rowData.name,
      externalId: rowData.externalId ?? "",
      targetStep,
      targetPhase,
      intent,
    });
  };

  return (
    <>
      {isOrgKind && (
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
        <ActionDropdown>
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
          {isOrgKind && canEditSchedule && (
            <ActionDropdownItem
              icon={<CalendarClock />}
              label="Edit Scan Schedule"
              onSelect={() => onOpenScheduleEditor()}
              disabled={scheduleProviderCount === 0}
            />
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
  selectedScheduleProviderIds = [],
  selectedScheduleProviders = [],
  onClearSelection,
  onOpenProviderWizard,
  onOpenOrganizationWizard,
  scanConfigs = [],
  scanConfigStatus = SCAN_CONFIGURATION_LIST_STATUS.AVAILABLE,
  currentScanConfigId = null,
  capability,
}: DataTableRowActionsProps) {
  const canEditSchedule =
    (capability ?? getScanScheduleCapability(isCloud())) ===
    SCAN_SCHEDULE_CAPABILITY.ADVANCED;
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isScheduleOpen, setIsScheduleOpen] = useState(false);
  const [scheduleState, setScheduleState] = useState<EditScanScheduleState>({
    kind: EDIT_SCAN_SCHEDULE_STATE.LOADING,
  });
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const [isScanConfigOpen, setIsScanConfigOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();
  const router = useRouter();

  const rowData = row.original;
  const isOrganizationRow = isProvidersOrganizationRow(rowData);
  const provider = isOrganizationRow ? null : rowData;
  const providerId = provider?.id ?? "";
  const providerType = provider?.attributes.provider ?? "aws";
  const providerUid = provider?.attributes.uid ?? "";
  const providerAlias = provider?.attributes.alias ?? null;
  const providerSecretId = provider?.relationships.secret.data?.id ?? null;
  const hasSecret = Boolean(provider?.relationships.secret.data);
  const isCloudProvider = isCloud() && Boolean(provider);
  const canManageScanConfig =
    isCloudProvider &&
    scanConfigStatus === SCAN_CONFIGURATION_LIST_STATUS.AVAILABLE;
  const scheduleProvider: ScanScheduleProvider | undefined = provider
    ? {
        providerId,
        providerType,
        providerUid,
        providerAlias,
      }
    : undefined;

  const orgGroupKind = isOrganizationRow ? rowData.groupKind : null;
  const childTestableIds = isOrganizationRow
    ? collectTestableChildProviderIds(rowData.subRows)
    : [];
  const childScheduleProviders = isOrganizationRow
    ? collectChildScheduleProviders(rowData.subRows)
    : [];
  const childScheduleProviderIds = isOrganizationRow ? rowData.providerIds : [];

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

  const openScheduleEditor = async (
    targetProviders: ScanScheduleProvider[] = scheduleProvider
      ? [scheduleProvider]
      : [],
    targetProviderIds: string[] = targetProviders.map(
      (target) => target.providerId,
    ),
  ) => {
    const targetProviderId = targetProviderIds[0];

    if (!targetProviderId) {
      setScheduleState({
        kind: EDIT_SCAN_SCHEDULE_STATE.ERROR,
        message: "Provider ID is not available.",
      });
      setIsScheduleOpen(true);
      return;
    }

    setScheduleState({ kind: EDIT_SCAN_SCHEDULE_STATE.LOADING });
    setIsScheduleOpen(true);

    const response = (await getSchedule(targetProviderId)) as
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

  // When this row is part of the selection, only show "Test Connection"
  if (hasSelection && isRowSelected) {
    const bulkCount =
      testableProviderIds.length > 1 ? ` (${testableProviderIds.length})` : "";
    const selectedScheduleProviderCount = selectedScheduleProviderIds.length;

    return (
      <>
        <EditScanScheduleModal
          open={isScheduleOpen}
          onOpenChange={setIsScheduleOpen}
          providers={selectedScheduleProviders}
          providerIds={selectedScheduleProviderIds}
          targetName="Selected providers"
          state={scheduleState}
          onSaved={onClearSelection}
        />
        <div className="relative flex items-center justify-end gap-2">
          <ActionDropdown>
            {canEditSchedule && selectedScheduleProviderCount > 0 && (
              <ActionDropdownItem
                icon={<CalendarClock />}
                label={`Edit Scan Schedule (${selectedScheduleProviderCount})`}
                onSelect={() =>
                  void openScheduleEditor(
                    selectedScheduleProviders,
                    selectedScheduleProviderIds,
                  )
                }
              />
            )}
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
      </>
    );
  }

  // Organization / Organization Unit row actions
  if (isProvidersOrganizationRow(rowData) && orgGroupKind) {
    return (
      <>
        <EditScanScheduleModal
          open={isScheduleOpen}
          onOpenChange={setIsScheduleOpen}
          providers={childScheduleProviders}
          providerIds={childScheduleProviderIds}
          targetName={rowData.name}
          targetId={rowData.externalId ?? undefined}
          state={scheduleState}
        />
        <OrgGroupDropdownActions
          rowData={rowData}
          loading={loading}
          canEditSchedule={canEditSchedule}
          hasSelection={hasSelection}
          testableProviderIds={testableProviderIds}
          childTestableIds={childTestableIds}
          scheduleProviderCount={childScheduleProviderIds.length}
          onClearSelection={onClearSelection}
          onBulkTest={handleBulkTest}
          onTestChildConnections={handleTestChildConnections}
          onOpenOrganizationWizard={onOpenOrganizationWizard}
          onOpenScheduleEditor={() =>
            void openScheduleEditor(
              childScheduleProviders,
              childScheduleProviderIds,
            )
          }
        />
      </>
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
      <EditScanScheduleModal
        open={isScheduleOpen}
        onOpenChange={setIsScheduleOpen}
        provider={scheduleProvider}
        state={scheduleState}
      />
      {canManageScanConfig && provider && (
        <ManageScanConfigModal
          open={isScanConfigOpen}
          onOpenChange={setIsScanConfigOpen}
          providerId={providerId}
          providerLabel={providerAlias || providerUid}
          scanConfigs={scanConfigs}
          currentConfigId={currentScanConfigId}
          onSaved={() => router.refresh()}
        />
      )}
      <div className="relative flex items-center justify-end gap-2">
        <ActionDropdown>
          <ActionDropdownItem
            icon={<Pencil />}
            label="Edit Provider Alias"
            onSelect={() => setIsEditOpen(true)}
          />
          <ActionDropdownItem
            icon={<Timer />}
            label="View Scan Jobs"
            onSelect={() => {
              // Same key the scans filter bar binds to (`provider__in`, by id) so
              // the provider is pre-selected and the filter works on every tab,
              // including Scheduled (whose endpoint only accepts provider id).
              const params = new URLSearchParams({
                "filter[provider__in]": providerId,
              });
              router.push(`/scans?${params.toString()}`);
            }}
          />
          {canEditSchedule && (
            <ActionDropdownItem
              icon={<CalendarClock />}
              label="Edit Scan Schedule"
              onSelect={() => void openScheduleEditor()}
            />
          )}
          {canManageScanConfig && (
            <ActionDropdownItem
              icon={<SlidersHorizontal />}
              label="Edit Scan Configuration"
              onSelect={() => setIsScanConfigOpen(true)}
            />
          )}
          {isCloudProvider &&
            scanConfigStatus === SCAN_CONFIGURATION_LIST_STATUS.UNAVAILABLE && (
              <ActionDropdownItem
                icon={<SlidersHorizontal />}
                label="Scan Configuration unavailable"
                description="Try again later."
                disabled
              />
            )}
          <ActionDropdownItem
            icon={<KeyRound />}
            label={hasSecret ? "Update Credentials" : "Add Credentials"}
            onSelect={() =>
              onOpenProviderWizard({
                providerId,
                providerType,
                providerUid,
                providerAlias,
                secretId: providerSecretId,
                mode: providerSecretId
                  ? PROVIDER_WIZARD_MODE.UPDATE
                  : PROVIDER_WIZARD_MODE.ADD,
              })
            }
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
