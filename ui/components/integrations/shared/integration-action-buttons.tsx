"use client";

import { LockIcon, Power, SettingsIcon, TestTube, Trash2Icon } from "lucide-react";

import { CustomButton } from "@/components/ui/custom";
import { IntegrationProps } from "@/types/integrations";

interface IntegrationActionButtonsProps {
  integration: IntegrationProps;
  onTestConnection: (id: string) => void;
  onEditConfiguration: (integration: IntegrationProps) => void;
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
      <CustomButton
        size="sm"
        variant="bordered"
        startContent={<TestTube size={14} />}
        onPress={() => onTestConnection(integration.id)}
        isLoading={isTesting}
        isDisabled={!integration.attributes.enabled}
        ariaLabel="Test connection"
        className="w-full sm:w-auto"
      >
        Test
      </CustomButton>
      <CustomButton
        size="sm"
        variant="bordered"
        startContent={<SettingsIcon size={14} />}
        onPress={() => onEditConfiguration(integration)}
        ariaLabel="Edit configuration"
        className="w-full sm:w-auto"
      >
        Config
      </CustomButton>
      {showCredentialsButton && (
        <CustomButton
          size="sm"
          variant="bordered"
          startContent={<LockIcon size={14} />}
          onPress={() => onEditCredentials(integration)}
          ariaLabel="Edit credentials"
          className="w-full sm:w-auto"
        >
          Credentials
        </CustomButton>
      )}
      <CustomButton
        size="sm"
        variant="bordered"
        color={integration.attributes.enabled ? "warning" : "primary"}
        startContent={<Power size={14} />}
        onPress={() => onToggleEnabled(integration)}
        ariaLabel={
          integration.attributes.enabled
            ? "Disable integration"
            : "Enable integration"
        }
        className="w-full sm:w-auto"
      >
        {integration.attributes.enabled ? "Disable" : "Enable"}
      </CustomButton>
      <CustomButton
        size="sm"
        color="danger"
        variant="bordered"
        startContent={<Trash2Icon size={14} />}
        onPress={() => onDelete(integration)}
        ariaLabel="Delete integration"
        className="w-full sm:w-auto"
      >
        Delete
      </CustomButton>
    </div>
  );
};