"use client";

import { Row } from "@tanstack/react-table";
import { Pencil, PlugZap, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { checkConnectionProvider } from "@/actions/providers/providers";
import { VerticalDotsIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import {
  ActionDropdown,
  ActionDropdownDangerZone,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { Modal } from "@/components/shadcn/modal";

import { EditForm } from "../forms";
import { DeleteForm } from "../forms/delete-form";

interface DataTableRowActionsProps<ProviderProps> {
  row: Row<ProviderProps>;
}

export function DataTableRowActions<ProviderProps>({
  row,
}: DataTableRowActionsProps<ProviderProps>) {
  const router = useRouter();
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const providerId = (row.original as { id: string }).id;
  const providerType = (row.original as any).attributes?.provider;
  const providerAlias = (row.original as any).attributes?.alias;
  const providerSecretId =
    (row.original as any).relationships?.secret?.data?.id || null;

  const handleTestConnection = async () => {
    setLoading(true);
    const formData = new FormData();
    formData.append("providerId", providerId);
    await checkConnectionProvider(formData);
    setLoading(false);
  };

  const hasSecret = (row.original as any).relationships?.secret?.data;

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
            onSelect={() =>
              router.push(
                `/providers/${hasSecret ? "update" : "add"}-credentials?type=${providerType}&id=${providerId}${providerSecretId ? `&secretId=${providerSecretId}` : ""}`,
              )
            }
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
