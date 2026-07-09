"use client";

import { Info, Plus, Trash2 } from "lucide-react";
import { useState } from "react";

import {
  deleteScanConfiguration,
  listScanConfigurations,
} from "@/actions/scan-configurations";
import { AccountsSelector } from "@/app/(prowler)/_overview/_components/accounts-selector";
import { BatchFiltersLayout } from "@/components/filters/batch-filters-layout";
import { ClearFiltersButton } from "@/components/filters/clear-filters-button";
import { Button, Card } from "@/components/shadcn";
import { useToast } from "@/components/shadcn";
import { CustomLink } from "@/components/shadcn/custom/custom-link";
import { Modal } from "@/components/shadcn/modal";
import { DataTable } from "@/components/shadcn/table";
import { DOCS_URLS } from "@/lib/external-urls";
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
}

export function ScanConfigurationsManager({
  initialConfigs,
  richProviders,
}: ScanConfigurationsManagerProps) {
  const [configs, setConfigs] =
    useState<ScanConfigurationData[]>(initialConfigs);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingConfig, setEditingConfig] =
    useState<ScanConfigurationData | null>(null);
  const [pendingDelete, setPendingDelete] =
    useState<ScanConfigurationData | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [providerFilter, setProviderFilter] = useState<string[]>([]);
  const [nameSearch, setNameSearch] = useState<string>("");
  const { toast } = useToast();

  const refresh = async () => {
    try {
      const fresh = await listScanConfigurations();
      setConfigs(fresh);
    } catch {
      // Keep the current table on a failed reload instead of clearing it.
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: "Failed to reload Scan Configurations. Please try again.",
      });
    }
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
    if (providerFilter.length > 0) {
      const attached = c.attributes.providers || [];
      const overlaps = providerFilter.some((pid) => attached.includes(pid));
      if (!overlaps) return false;
    }
    if (nameSearch) {
      const needle = nameSearch.trim().toLowerCase();
      if (!c.attributes.name.toLowerCase().includes(needle)) return false;
    }
    return true;
  });

  const noMatchForProvider =
    providerFilter.length > 0 &&
    filteredConfigs.length === 0 &&
    !nameSearch.trim();

  const hasAnyFilter =
    providerFilter.length > 0 || nameSearch.trim().length > 0;

  const handleProvidersChange = (_filterKey: string, values: string[]) => {
    setProviderFilter(values);
  };

  const clearFilters = () => {
    setProviderFilter([]);
    setNameSearch("");
  };

  return (
    <>
      <div className="text-text-neutral-secondary mb-6 flex max-w-3xl items-start gap-2 text-sm">
        <Info className="mt-0.5 size-4 shrink-0" />
        <p>
          By default, every provider uses Prowler&apos;s built-in configuration
          baseline. Create a Scan Configuration to override specific values and
          attach it to the providers that should use it. Learn more{" "}
          <CustomLink size="sm" href={DOCS_URLS.SCAN_CONFIGURATION}>
            here
          </CustomLink>
          .
        </p>
      </div>

      <div className="mb-6">
        <BatchFiltersLayout
          testIdPrefix="scan-configuration"
          controlsClassName="gap-3"
          controls={
            <>
              <div className={FILTER_CONTROL_COLUMN_CLASS}>
                <AccountsSelector
                  providers={richProviders}
                  onBatchChange={handleProvidersChange}
                  selectedValues={providerFilter}
                />
              </div>
              {hasAnyFilter && (
                <ClearFiltersButton
                  showCount
                  pendingCount={
                    providerFilter.length + (nameSearch.trim() ? 1 : 0)
                  }
                  onClear={clearFilters}
                />
              )}
              <div className="md:ml-auto">
                <Button size="lg" onClick={openCreate}>
                  <Plus className="size-4" />
                  New Scan Configuration
                </Button>
              </div>
            </>
          }
        />
      </div>

      {noMatchForProvider ? (
        <Card variant="base" padding="xl">
          <div className="text-center">
            <p className="text-text-neutral-secondary text-sm font-medium">
              {providerFilter.length === 1
                ? "No Scan Configuration is attached to this provider."
                : "No Scan Configuration is attached to any of the selected providers."}
            </p>
            <p className="text-text-neutral-tertiary mt-1 text-sm">
              The next scan{providerFilter.length === 1 ? "" : "s"} will use the
              built-in defaults shipped with Prowler. Attach a Scan
              Configuration from the editor to override them.
            </p>
          </div>
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
      />

      <Modal
        open={!!pendingDelete}
        onOpenChange={(open) => !open && setPendingDelete(null)}
        title="Delete Scan Configuration"
        size="md"
      >
        <div className="flex flex-col gap-4">
          <p className="text-text-neutral-secondary text-sm">
            Are you sure you want to delete{" "}
            <strong>{pendingDelete?.attributes.name}</strong>? Attached
            providers will fall back to the built-in scan defaults on their next
            scan.
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
