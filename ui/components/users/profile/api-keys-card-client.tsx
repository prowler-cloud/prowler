"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  Button,
  Card,
  CardAction,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn";
import { CustomLink } from "@/components/shadcn/custom/custom-link";
import { DataTable } from "@/components/shadcn/table";
import { MetaDataProps } from "@/types";

import { ApiKeySuccessModal } from "./api-key-success-modal";
import { createApiKeyColumns } from "./api-keys/column-api-keys";
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

  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isSuccessModalOpen, setIsSuccessModalOpen] = useState(false);
  const [isRevokeModalOpen, setIsRevokeModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);

  const handleCreateSuccess = (apiKey: string) => {
    setCreatedApiKey(apiKey);
    setIsSuccessModalOpen(true);
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
    setIsRevokeModalOpen(true);
  };

  const handleEditClick = (apiKey: EnrichedApiKey) => {
    setSelectedApiKey(apiKey);
    setIsEditModalOpen(true);
  };

  const columns = createApiKeyColumns(handleEditClick, handleRevokeClick);

  return (
    <>
      <Card variant="base" padding="none" className="p-4">
        <CardHeader>
          <div className="flex flex-col gap-2">
            <CardTitle>API Keys</CardTitle>
            <p className="text-xs text-gray-500">
              Manage API keys for programmatic access.{" "}
              <CustomLink href="https://docs.prowler.com/user-guide/tutorials/prowler-app-api-keys">
                Read the docs
              </CustomLink>
            </p>
          </div>
          <CardAction>
            <Button
              variant="default"
              size="sm"
              onClick={() => setIsCreateModalOpen(true)}
            >
              Create API Key
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent>
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
        </CardContent>
      </Card>

      {/* Modals */}
      <CreateApiKeyModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSuccess={handleCreateSuccess}
      />

      {createdApiKey && (
        <ApiKeySuccessModal
          isOpen={isSuccessModalOpen}
          onClose={() => setIsSuccessModalOpen(false)}
          apiKey={createdApiKey}
        />
      )}

      <RevokeApiKeyModal
        isOpen={isRevokeModalOpen}
        onClose={() => setIsRevokeModalOpen(false)}
        apiKey={selectedApiKey}
        onSuccess={handleRevokeSuccess}
      />

      <EditApiKeyNameModal
        isOpen={isEditModalOpen}
        onClose={() => setIsEditModalOpen(false)}
        apiKey={selectedApiKey}
        onSuccess={handleEditSuccess}
        existingApiKeys={initialApiKeys}
      />
    </>
  );
};
