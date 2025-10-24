"use client";

import { Card, CardBody, CardHeader } from "@heroui/card";
import { useDisclosure } from "@heroui/use-disclosure";
import { Plus } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { CustomButton } from "@/components/ui/custom/custom-button";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { DataTable } from "@/components/ui/table";
import { MetaDataProps } from "@/types";

import { ApiKeySuccessModal } from "./api-key-success-modal";
import { createApiKeyColumns } from "./api-keys/column-api-keys";
import { ICON_SIZE } from "./api-keys/constants";
import { EnrichedApiKey } from "./api-keys/types";
import { CreateApiKeyModal } from "./create-api-key-modal";
import { EditApiKeyNameModal } from "./edit-api-key-name-modal";
import { RevokeApiKeyModal } from "./revoke-api-key-modal";

interface ApiKeysCardClientProps {
  initialApiKeys: EnrichedApiKey[];
  metadata?: MetaDataProps;
}

export const ApiKeysCardClient = ({
  initialApiKeys,
  metadata,
}: ApiKeysCardClientProps) => {
  const router = useRouter();
  const [selectedApiKey, setSelectedApiKey] = useState<EnrichedApiKey | null>(
    null,
  );
  const [createdApiKey, setCreatedApiKey] = useState<string | null>(null);

  const createModal = useDisclosure();
  const successModal = useDisclosure();
  const revokeModal = useDisclosure();
  const editModal = useDisclosure();

  const handleCreateSuccess = (apiKey: string) => {
    setCreatedApiKey(apiKey);
    successModal.onOpen();
    router.refresh();
  };

  const handleRevokeSuccess = () => {
    router.refresh();
  };

  const handleEditSuccess = () => {
    router.refresh();
  };

  const handleRevokeClick = (apiKey: EnrichedApiKey) => {
    setSelectedApiKey(apiKey);
    revokeModal.onOpen();
  };

  const handleEditClick = (apiKey: EnrichedApiKey) => {
    setSelectedApiKey(apiKey);
    editModal.onOpen();
  };

  const columns = createApiKeyColumns(handleEditClick, handleRevokeClick);

  return (
    <>
      <Card className="dark:bg-prowler-blue-400">
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <div className="flex flex-col gap-1">
            <h4 className="text-lg font-bold">API Keys</h4>
            <p className="text-xs text-gray-500">
              Manage API keys for programmatic access.{" "}
              <CustomLink href="https://docs.prowler.com/user-guide/providers/prowler-app-api-keys">
                Read the docs
              </CustomLink>
            </p>
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
            <DataTable
              columns={columns}
              data={initialApiKeys}
              metadata={metadata}
            />
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

      <RevokeApiKeyModal
        isOpen={revokeModal.isOpen}
        onClose={revokeModal.onClose}
        apiKey={selectedApiKey}
        onSuccess={handleRevokeSuccess}
      />

      <EditApiKeyNameModal
        isOpen={editModal.isOpen}
        onClose={editModal.onClose}
        apiKey={selectedApiKey}
        onSuccess={handleEditSuccess}
        existingApiKeys={initialApiKeys}
      />
    </>
  );
};
