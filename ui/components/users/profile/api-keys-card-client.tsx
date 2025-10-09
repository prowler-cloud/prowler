"use client";

import { Card, CardBody, CardHeader } from "@heroui/card";
import { useDisclosure } from "@heroui/use-disclosure";
import { Plus } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { CustomButton } from "@/components/ui/custom/custom-button";
import { DataTable } from "@/components/ui/table";

import { ApiKeySuccessModal } from "./api-key-success-modal";
import { createApiKeyColumns } from "./api-keys/column-api-keys";
import { ICON_SIZE } from "./api-keys/constants";
import { ApiKeyData, IncludedResource } from "./api-keys/types";
import { CreateApiKeyModal } from "./create-api-key-modal";
import { DeleteApiKeyModal } from "./delete-api-key-modal";
import { EditApiKeyNameModal } from "./edit-api-key-name-modal";

interface ApiKeysCardClientProps {
  initialApiKeys: ApiKeyData[];
  included: IncludedResource[];
}

export const ApiKeysCardClient = ({
  initialApiKeys,
  included,
}: ApiKeysCardClientProps) => {
  const router = useRouter();
  const [selectedApiKey, setSelectedApiKey] = useState<ApiKeyData | null>(null);
  const [createdApiKey, setCreatedApiKey] = useState<string | null>(null);

  const createModal = useDisclosure();
  const successModal = useDisclosure();
  const deleteModal = useDisclosure();
  const editModal = useDisclosure();

  const handleCreateSuccess = (apiKey: string) => {
    setCreatedApiKey(apiKey);
    successModal.onOpen();
    router.refresh();
  };

  const handleDeleteSuccess = () => {
    router.refresh();
  };

  const handleEditSuccess = () => {
    router.refresh();
  };

  const handleDeleteClick = (apiKey: ApiKeyData) => {
    setSelectedApiKey(apiKey);
    deleteModal.onOpen();
  };

  const handleEditClick = (apiKey: ApiKeyData) => {
    setSelectedApiKey(apiKey);
    editModal.onOpen();
  };

  const columns = createApiKeyColumns(
    handleEditClick,
    handleDeleteClick,
    included,
  );

  return (
    <>
      <Card className="dark:bg-prowler-blue-400">
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <div className="flex flex-col gap-1">
            <h4 className="text-lg font-bold">API Keys</h4>
            <p className="text-xs">Manage API keys for programmatic access</p>
          </div>
          <CustomButton
            ariaLabel="Create new API key"
            color="action"
            size="sm"
            startContent={<Plus size={ICON_SIZE} />}
            onPress={createModal.onOpen}
          >
            Create API Key
          </CustomButton>
        </CardHeader>
        <CardBody>
          {initialApiKeys.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 py-12">
              <p className="text-sm">No API keys created yet.</p>
            </div>
          ) : (
            <DataTable columns={columns} data={initialApiKeys} />
          )}
        </CardBody>
      </Card>

      {/* Modals */}
      <CreateApiKeyModal
        isOpen={createModal.isOpen}
        onClose={createModal.onClose}
        onSuccess={handleCreateSuccess}
      />

      {createdApiKey && (
        <ApiKeySuccessModal
          isOpen={successModal.isOpen}
          onClose={successModal.onClose}
          apiKey={createdApiKey}
        />
      )}

      <DeleteApiKeyModal
        isOpen={deleteModal.isOpen}
        onClose={deleteModal.onClose}
        apiKey={selectedApiKey}
        onSuccess={handleDeleteSuccess}
      />

      <EditApiKeyNameModal
        isOpen={editModal.isOpen}
        onClose={editModal.onClose}
        apiKey={selectedApiKey}
        onSuccess={handleEditSuccess}
      />
    </>
  );
};
