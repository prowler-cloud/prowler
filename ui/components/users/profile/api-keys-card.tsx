"use client";

import { useEffect, useState } from "react";

import { Button } from "@heroui/button";
import { Card, CardBody, CardHeader } from "@heroui/card";
import { Chip } from "@heroui/chip";
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
import { formatDistanceToNow } from "date-fns";
import { MoreVertical, Pencil, Plus, Trash2 } from "lucide-react";

import { getApiKeys } from "@/actions/api-keys/api-keys";
import {
  API_KEY_STATUS,
  ApiKeyData,
  ApiKeyStatus,
  getApiKeyStatus,
} from "@/types/api-keys";

import { ApiKeySuccessModal } from "./api-key-success-modal";
import { CreateApiKeyModal } from "./create-api-key-modal";
import { DeleteApiKeyModal } from "./delete-api-key-modal";
import { EditApiKeyNameModal } from "./edit-api-key-name-modal";

const getStatusColor = (
  status: ApiKeyStatus,
): "success" | "danger" | "warning" => {
  switch (status) {
    case API_KEY_STATUS.ACTIVE:
      return "success";
    case API_KEY_STATUS.REVOKED:
      return "danger";
    case API_KEY_STATUS.EXPIRED:
      return "warning";
    default:
      return "success";
  }
};

const getStatusLabel = (status: ApiKeyStatus): string => {
  switch (status) {
    case API_KEY_STATUS.ACTIVE:
      return "Active";
    case API_KEY_STATUS.REVOKED:
      return "Revoked";
    case API_KEY_STATUS.EXPIRED:
      return "Expired";
    default:
      return "Unknown";
  }
};

export const ApiKeysCard = () => {
  const [apiKeys, setApiKeys] = useState<ApiKeyData[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedApiKey, setSelectedApiKey] = useState<ApiKeyData | null>(null);
  const [createdApiKey, setCreatedApiKey] = useState<string | null>(null);

  const createModal = useDisclosure();
  const successModal = useDisclosure();
  const deleteModal = useDisclosure();
  const editModal = useDisclosure();

  const loadApiKeys = async () => {
    setIsLoading(true);
    const response = await getApiKeys();
    if (response?.data) {
      // Filter out revoked keys (they are effectively deleted)
      const activeKeys = response.data.filter(
        (key) => !key.attributes.revoked,
      );
      setApiKeys(activeKeys);
    }
    setIsLoading(false);
  };

  useEffect(() => {
    loadApiKeys();
  }, []);

  const handleCreateSuccess = (apiKey: string) => {
    setCreatedApiKey(apiKey);
    successModal.onOpen();
    loadApiKeys();
  };

  const handleDeleteClick = (apiKey: ApiKeyData) => {
    setSelectedApiKey(apiKey);
    deleteModal.onOpen();
  };

  const handleEditClick = (apiKey: ApiKeyData) => {
    setSelectedApiKey(apiKey);
    editModal.onOpen();
  };

  const handleOperationSuccess = () => {
    loadApiKeys();
  };

  const columns = [
    { key: "name", label: "NAME" },
    { key: "prefix", label: "PREFIX" },
    { key: "created", label: "CREATED" },
    { key: "last_used", label: "LAST USED" },
    { key: "expires", label: "EXPIRES" },
    { key: "status", label: "STATUS" },
    { key: "actions", label: "" },
  ];

  const renderCell = (apiKey: ApiKeyData, columnKey: React.Key) => {
    const status = getApiKeyStatus(apiKey);

    switch (columnKey) {
      case "name":
        return (
          <div className="flex flex-col">
            <p className="text-sm font-medium text-white">
              {apiKey.attributes.name || "Unnamed"}
            </p>
          </div>
        );

      case "prefix":
        return (
          <code className="rounded bg-slate-700 px-2 py-1 text-xs font-mono text-slate-300">
            {apiKey.attributes.prefix}
          </code>
        );

      case "created":
        return (
          <p className="text-sm text-slate-400">
            {formatDistanceToNow(new Date(apiKey.attributes.inserted_at), {
              addSuffix: true,
            })}
          </p>
        );

      case "last_used":
        return (
          <p className="text-sm text-slate-400">
            {apiKey.attributes.last_used_at
              ? formatDistanceToNow(new Date(apiKey.attributes.last_used_at), {
                  addSuffix: true,
                })
              : "Never"}
          </p>
        );

      case "expires":
        return (
          <p className="text-sm text-slate-400">
            {formatDistanceToNow(new Date(apiKey.attributes.expires_at), {
              addSuffix: true,
            })}
          </p>
        );

      case "status":
        return (
          <Chip color={getStatusColor(status)} size="sm" variant="flat">
            {getStatusLabel(status)}
          </Chip>
        );

      case "actions":
        return (
          <div className="flex justify-end">
            <Dropdown>
              <DropdownTrigger>
                <Button isIconOnly size="sm" variant="light">
                  <MoreVertical size={16} />
                </Button>
              </DropdownTrigger>
              <DropdownMenu aria-label="API Key actions">
                <DropdownItem
                  key="edit"
                  startContent={<Pencil size={16} />}
                  onPress={() => handleEditClick(apiKey)}
                >
                  Edit name
                </DropdownItem>
                <DropdownItem
                  key="delete"
                  className="text-danger"
                  color="danger"
                  startContent={<Trash2 size={16} />}
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
            startContent={<Plus size={16} />}
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
                startContent={<Plus size={16} />}
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
              <TableHeader columns={columns}>
                {(column) => (
                  <TableColumn
                    key={column.key}
                    align={column.key === "actions" ? "end" : "start"}
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
        onSuccess={handleOperationSuccess}
      />

      <EditApiKeyNameModal
        isOpen={editModal.isOpen}
        onClose={editModal.onClose}
        apiKey={selectedApiKey}
        onSuccess={handleOperationSuccess}
      />
    </>
  );
};
