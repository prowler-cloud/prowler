"use client";

import { Row } from "@tanstack/react-table";
import { Pencil, PlugZap, Trash2 } from "lucide-react";
import { useState } from "react";

import { checkConnectionProvider } from "@/actions/providers/providers";
import { VerticalDotsIcon } from "@/components/icons";
import { ProviderWizardModal } from "@/components/providers/wizard";
import { Button } from "@/components/shadcn";
import {
  ActionDropdown,
  ActionDropdownDangerZone,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { Modal } from "@/components/shadcn/modal";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";
import { ProviderProps } from "@/types/providers";

import { EditForm } from "../forms";
import { DeleteForm } from "../forms/delete-form";

interface DataTableRowActionsProps {
  row: Row<ProviderProps>;
}

export function DataTableRowActions({ row }: DataTableRowActionsProps) {
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const [isWizardOpen, setIsWizardOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const provider = row.original;
  const providerId = provider.id;
  const providerType = provider.attributes.provider;
  const providerUid = provider.attributes.uid;
  const providerAlias = provider.attributes.alias ?? null;
  const providerSecretId = provider.relationships.secret.data?.id ?? null;

  const handleTestConnection = async () => {
    setLoading(true);
    const formData = new FormData();
    formData.append("providerId", providerId);
    await checkConnectionProvider(formData);
    setLoading(false);
  };

  const hasSecret = Boolean(provider.relationships.secret.data);

  return (
    <>
      <Modal
        open={isEditOpen}
        onOpenChange={setIsEditOpen}
        title="Edit Provider Alias"
      >
        <EditForm
          providerId={providerId}
          providerAlias={providerAlias}
          setIsOpen={setIsEditOpen}
        />
      </Modal>
      <Modal
        open={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Are you absolutely sure?"
        description="This action cannot be undone. This will permanently delete your provider account and remove your data from the server."
      >
        <DeleteForm providerId={providerId} setIsOpen={setIsDeleteOpen} />
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
              <VerticalDotsIcon className="text-slate-400" />
            </Button>
          }
        >
          <ActionDropdownItem
            icon={<Pencil />}
            label={hasSecret ? "Update Credentials" : "Add Credentials"}
            onSelect={() => setIsWizardOpen(true)}
          />
          <ActionDropdownItem
            icon={<PlugZap />}
            label={loading ? "Testing..." : "Test Connection"}
            description={
              hasSecret && !loading
                ? "Check the provider connection"
                : loading
                  ? "Checking provider connection"
                  : "Add credentials to test the connection"
            }
            onSelect={(e) => {
              e.preventDefault();
              handleTestConnection();
            }}
            disabled={!hasSecret || loading}
          />
          <ActionDropdownItem
            icon={<Pencil />}
            label="Edit Provider Alias"
            onSelect={() => setIsEditOpen(true)}
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
