"use client";

import { Button } from "@heroui/button";
import { Card, CardBody, CardHeader } from "@heroui/card";
import {
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
} from "@heroui/dropdown";
import {
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
} from "@heroui/table";
import { useDisclosure } from "@heroui/use-disclosure";
import { MoreVertical, Pencil, Plus, Trash2 } from "lucide-react";
import { useState } from "react";

import { ApiKeyData } from "@/types/api-keys";

import { ApiKeySuccessModal } from "./api-key-success-modal";
import {
  API_KEY_COLUMN_KEYS,
  API_KEY_COLUMNS,
  ICON_SIZE,
} from "./api-keys/constants";
import {
  DateCell,
  LastUsedCell,
  NameCell,
  PrefixCell,
  StatusCell,
} from "./api-keys/table-cells";
import { CreateApiKeyModal } from "./create-api-key-modal";
import { DeleteApiKeyModal } from "./delete-api-key-modal";
import { EditApiKeyNameModal } from "./edit-api-key-name-modal";
import { useApiKeys } from "./hooks/use-api-keys";

export const ApiKeysCard = () => {
  const { apiKeys, isLoading, refetch } = useApiKeys();
  const [selectedApiKey, setSelectedApiKey] = useState<ApiKeyData | null>(null);
  const [createdApiKey, setCreatedApiKey] = useState<string | null>(null);

  const createModal = useDisclosure();
  const successModal = useDisclosure();
  const deleteModal = useDisclosure();
  const editModal = useDisclosure();

  const handleCreateSuccess = (apiKey: string) => {
    setCreatedApiKey(apiKey);
    successModal.onOpen();
    refetch();
  };

  const handleDeleteClick = (apiKey: ApiKeyData) => {
    setSelectedApiKey(apiKey);
    deleteModal.onOpen();
  };

  const handleEditClick = (apiKey: ApiKeyData) => {
    setSelectedApiKey(apiKey);
    editModal.onOpen();
  };

  const renderCell = (apiKey: ApiKeyData, columnKey: React.Key) => {
    switch (columnKey) {
      case API_KEY_COLUMN_KEYS.NAME:
        return <NameCell apiKey={apiKey} />;

      case API_KEY_COLUMN_KEYS.PREFIX:
        return <PrefixCell apiKey={apiKey} />;

      case API_KEY_COLUMN_KEYS.CREATED:
        return <DateCell date={apiKey.attributes.inserted_at} />;

      case API_KEY_COLUMN_KEYS.LAST_USED:
        return <LastUsedCell apiKey={apiKey} />;

      case API_KEY_COLUMN_KEYS.EXPIRES:
        return <DateCell date={apiKey.attributes.expires_at} />;

      case API_KEY_COLUMN_KEYS.STATUS:
        return <StatusCell apiKey={apiKey} />;

      case API_KEY_COLUMN_KEYS.ACTIONS:
        return (
          <div className="flex justify-end">
            <Dropdown>
              <DropdownTrigger>
                <Button isIconOnly size="sm" variant="light">
                  <MoreVertical size={ICON_SIZE} />
                </Button>
              </DropdownTrigger>
              <DropdownMenu aria-label="API Key actions">
                <DropdownItem
                  key="edit"
                  startContent={<Pencil size={ICON_SIZE} />}
                  onPress={() => handleEditClick(apiKey)}
                >
                  Edit name
                </DropdownItem>
                <DropdownItem
                  key="delete"
                  className="text-danger"
                  color="danger"
                  startContent={<Trash2 size={ICON_SIZE} />}
                  onPress={() => handleDeleteClick(apiKey)}
                >
                  Delete
                </DropdownItem>
              </DropdownMenu>
            </Dropdown>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <>
      <Card className="bg-card-bg">
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <div className="flex flex-col gap-1">
            <h4 className="text-lg font-bold text-white">API Keys</h4>
            <p className="text-xs text-slate-400">
              Manage API keys for programmatic access
            </p>
          </div>
          <Button
            color="success"
            size="sm"
            startContent={<Plus size={ICON_SIZE} />}
            onPress={createModal.onOpen}
          >
            Create API Key
          </Button>
        </CardHeader>
        <CardBody>
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <p className="text-sm text-slate-400">Loading API keys...</p>
            </div>
          ) : apiKeys.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 py-12">
              <p className="text-sm text-slate-400">No API keys created yet.</p>
              <Button
                color="success"
                variant="flat"
                size="sm"
                startContent={<Plus size={ICON_SIZE} />}
                onPress={createModal.onOpen}
              >
                Create your first API key
              </Button>
            </div>
          ) : (
            <Table
              aria-label="API Keys table"
              classNames={{
                wrapper: "bg-transparent shadow-none",
                th: "bg-slate-800 text-slate-300",
                td: "border-b border-slate-700",
              }}
            >
              <TableHeader columns={API_KEY_COLUMNS}>
                {(column) => (
                  <TableColumn
                    key={column.key}
                    align={
                      column.key === API_KEY_COLUMN_KEYS.ACTIONS
                        ? "end"
                        : "start"
                    }
                  >
                    {column.label}
                  </TableColumn>
                )}
              </TableHeader>
              <TableBody items={apiKeys}>
                {(item) => (
                  <TableRow key={item.id}>
                    {(columnKey) => (
                      <TableCell>{renderCell(item, columnKey)}</TableCell>
                    )}
                  </TableRow>
                )}
              </TableBody>
            </Table>
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
        onSuccess={refetch}
      />

      <EditApiKeyNameModal
        isOpen={editModal.isOpen}
        onClose={editModal.onClose}
        apiKey={selectedApiKey}
        onSuccess={refetch}
      />
    </>
  );
};
