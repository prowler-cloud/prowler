"use client";

import { Plus, Trash2 } from "lucide-react";
import { useState } from "react";

import {
  deleteScanConfiguration,
  listScanConfigurations,
} from "@/actions/scan-configurations";
import { AccountsSelector } from "@/app/(prowler)/_overview/_components/accounts-selector";
import { BatchFiltersLayout } from "@/components/filters/batch-filters-layout";
import { ClearFiltersButton } from "@/components/filters/clear-filters-button";
import { Button, Card } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/ui";
import { DataTable } from "@/components/ui/table";
import { ProviderProps } from "@/types/providers";
import { ScanConfigurationData } from "@/types/scan-configurations";

import { ScanConfigurationEditor } from "./scan-configuration-editor";
import { createScanConfigurationsColumns } from "./scan-configurations-columns";

// Same column basis classes as `FindingsFilters` so the controls align across
// breakpoints with the rest of the product.
const FILTER_CONTROL_COLUMN_CLASS =
  "min-w-0 flex-none basis-full sm:basis-[calc((100%_-_0.75rem)/2)] lg:basis-[calc((100%_-_1.5rem)/3)] xl:basis-[calc((100%_-_2.25rem)/4)] 2xl:basis-[calc((100%_-_3rem)/5)]";

interface ScanConfigurationsManagerProps {
  initialConfigs: ScanConfigurationData[];
  richProviders: ProviderProps[];
  schema: Record<string, unknown> | null;
}

export function ScanConfigurationsManager({
  initialConfigs,
  richProviders,
  schema,
}: ScanConfigurationsManagerProps) {
  const [configs, setConfigs] =
    useState<ScanConfigurationData[]>(initialConfigs);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingConfig, setEditingConfig] =
    useState<ScanConfigurationData | null>(null);
  const [pendingDelete, setPendingDelete] =
    useState<ScanConfigurationData | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [accountFilter, setAccountFilter] = useState<string[]>([]);
  const [nameSearch, setNameSearch] = useState<string>("");
  const { toast } = useToast();

  const refresh = async () => {
    const fresh = await listScanConfigurations();
    setConfigs(fresh);
  };

  const openCreate = () => {
    setEditingConfig(null);
    setEditorOpen(true);
  };

  const openEdit = (config: ScanConfigurationData) => {
    setEditingConfig(config);
    setEditorOpen(true);
  };

  const handleEditorClose = (saved: boolean) => {
    setEditorOpen(false);
    setEditingConfig(null);
    if (saved) {
      void refresh();
    }
  };

  const handleDelete = async () => {
    if (!pendingDelete) return;
    setIsDeleting(true);
    const formData = new FormData();
    formData.append("id", pendingDelete.id);

    try {
      const result = await deleteScanConfiguration(null, formData);
      if (result?.success) {
        toast({
          title: "Scan Configuration deleted",
          description: result.success,
        });
        await refresh();
      } else if (result?.errors?.general) {
        toast({
          variant: "destructive",
          title: "Oops! Something went wrong",
          description: result.errors.general,
        });
      }
    } catch {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: "Error deleting Scan Configuration. Please try again.",
      });
    } finally {
      setIsDeleting(false);
      setPendingDelete(null);
    }
  };

  const columns = createScanConfigurationsColumns(
    (cfg) => openEdit(cfg),
    (cfg) => setPendingDelete(cfg),
  );

  const filteredConfigs = configs.filter((c) => {
    if (accountFilter.length > 0) {
      const attached = c.attributes.providers || [];
      const overlaps = accountFilter.some((pid) => attached.includes(pid));
      if (!overlaps) return false;
    }
    if (nameSearch) {
      const needle = nameSearch.trim().toLowerCase();
      if (!c.attributes.name.toLowerCase().includes(needle)) return false;
    }
    return true;
  });

  const noMatchForAccount =
    accountFilter.length > 0 && filteredConfigs.length === 0 && !nameSearch;

  const hasAnyFilter = accountFilter.length > 0 || nameSearch.length > 0;

  const handleAccountsChange = (_filterKey: string, values: string[]) => {
    setAccountFilter(values);
  };

  const clearFilters = () => {
    setAccountFilter([]);
    setNameSearch("");
  };

  return (
    <>
      <div className="mb-6">
        <BatchFiltersLayout
          testIdPrefix="scan-configuration"
          controlsClassName="gap-3"
          controls={
            <>
              <div className={FILTER_CONTROL_COLUMN_CLASS}>
                <AccountsSelector
                  providers={richProviders}
                  onBatchChange={handleAccountsChange}
                  selectedValues={accountFilter}
                />
              </div>
              {hasAnyFilter && (
                <ClearFiltersButton
                  showCount
                  pendingCount={
                    accountFilter.length + (nameSearch.trim() ? 1 : 0)
                  }
                  onClear={clearFilters}
                />
              )}
              <Button size="lg" onClick={openCreate} className="md:ml-auto">
                <Plus className="size-4" />
                New Scan Configuration
              </Button>
            </>
          }
        />
      </div>

      {noMatchForAccount ? (
        <Card variant="base" className="p-8 text-center">
          <p className="text-default-700 text-sm font-medium">
            {accountFilter.length === 1
              ? "No Scan Configuration is attached to this account."
              : "No Scan Configuration is attached to any of the selected accounts."}
          </p>
          <p className="text-default-500 mt-1 text-sm">
            The next scan{accountFilter.length === 1 ? "" : "s"} will use the
            built-in defaults shipped with Prowler. Attach a Scan Configuration
            from the editor to override them.
          </p>
        </Card>
      ) : (
        <DataTable
          columns={columns}
          data={filteredConfigs}
          showSearch
          controlledSearch={nameSearch}
          onSearchChange={setNameSearch}
          // No-op commit: presence of this prop disables the 500ms debounce
          // inside DataTableSearch so the local filter applies on every
          // keystroke instead of half a second after typing.
          onSearchCommit={() => undefined}
          searchPlaceholder="Search by config name..."
        />
      )}

      <ScanConfigurationEditor
        open={editorOpen}
        onClose={handleEditorClose}
        richProviders={richProviders}
        existingConfigs={configs}
        config={editingConfig}
        schema={schema}
      />

      <Modal
        open={!!pendingDelete}
        onOpenChange={(open) => !open && setPendingDelete(null)}
        title="Delete Scan Configuration"
        size="md"
      >
        <div className="flex flex-col gap-4">
          <p className="text-default-600 text-sm">
            Are you sure you want to delete{" "}
            <strong>{pendingDelete?.attributes.name}</strong>? Attached accounts
            will fall back to the built-in scan defaults on their next scan.
          </p>
          <div className="flex w-full justify-end gap-4">
            <Button
              type="button"
              variant="ghost"
              size="lg"
              onClick={() => setPendingDelete(null)}
              disabled={isDeleting}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              size="lg"
              disabled={isDeleting}
              onClick={handleDelete}
            >
              <Trash2 className="size-4" />
              {isDeleting ? "Deleting..." : "Delete"}
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
