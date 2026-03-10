"use client";

import {
  LockIcon,
  Power,
  SettingsIcon,
  TestTube,
  Trash2Icon,
} from "lucide-react";

import { Button } from "@/components/shadcn";
import { IntegrationProps } from "@/types/integrations";

interface IntegrationActionButtonsProps {
  integration: IntegrationProps;
  onTestConnection: (id: string) => void;
  onEditConfiguration?: (integration: IntegrationProps) => void;
  onEditCredentials: (integration: IntegrationProps) => void;
  onToggleEnabled: (integration: IntegrationProps) => void;
  onDelete: (integration: IntegrationProps) => void;
  isTesting?: boolean;
  showCredentialsButton?: boolean;
}

export const IntegrationActionButtons = ({
  integration,
  onTestConnection,
  onEditConfiguration,
  onEditCredentials,
  onToggleEnabled,
  onDelete,
  isTesting = false,
  showCredentialsButton = true,
}: IntegrationActionButtonsProps) => {
  return (
    <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
      <Button
        size="sm"
        variant="outline"
        onClick={() => onTestConnection(integration.id)}
        disabled={!integration.attributes.enabled || isTesting}
        className="w-full sm:w-auto"
      >
        <TestTube size={14} />
        {isTesting ? "Testing..." : "Test"}
      </Button>
      {onEditConfiguration && (
        <Button
          size="sm"
          variant="outline"
          onClick={() => onEditConfiguration(integration)}
          className="w-full sm:w-auto"
        >
          <SettingsIcon size={14} />
          Config
        </Button>
      )}
      {showCredentialsButton && (
        <Button
          size="sm"
          variant="outline"
          onClick={() => onEditCredentials(integration)}
          className="w-full sm:w-auto"
        >
          <LockIcon size={14} />
          Credentials
        </Button>
      )}
      <Button
        size="sm"
        variant="outline"
        onClick={() => onToggleEnabled(integration)}
        disabled={isTesting}
        className="w-full sm:w-auto"
      >
        <Power size={14} />
        {integration.attributes.enabled ? "Disable" : "Enable"}
      </Button>
      <Button
        size="sm"
        variant="outline"
        onClick={() => onDelete(integration)}
        className="w-full text-red-600 hover:bg-red-50 hover:text-red-700 sm:w-auto dark:text-red-400 dark:hover:bg-red-950 dark:hover:text-red-300"
      >
        <Trash2Icon size={14} />
        Delete
      </Button>
    </div>
  );
};
