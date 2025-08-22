"use client";

import { Card, CardBody, CardHeader, Chip } from "@nextui-org/react";
import { format } from "date-fns";
import {
  PlusIcon,
  Power,
  SettingsIcon,
  TestTube,
  Trash2Icon,
} from "lucide-react";
import { useState } from "react";

import {
  deleteIntegration,
  testIntegrationConnection,
  updateIntegration,
} from "@/actions/integrations";
import { AWSSecurityHubIcon } from "@/components/icons/services/IconServices";
import { useToast } from "@/components/ui";
import { CustomAlertModal, CustomButton } from "@/components/ui/custom";
import { DataTablePagination } from "@/components/ui/table/data-table-pagination";
import { MetaDataProps } from "@/types";
import { IntegrationProps } from "@/types/integrations";
import { ProviderProps } from "@/types/providers";

import { SecurityHubIntegrationForm } from "./security-hub-integration-form";
import { SecurityHubIntegrationCardSkeleton } from "./skeleton-security-hub-integration-card";

interface SecurityHubIntegrationsManagerProps {
  integrations: IntegrationProps[];
  providers: ProviderProps[];
  metadata?: MetaDataProps;
}

export const SecurityHubIntegrationsManager = ({
  integrations,
  providers,
  metadata,
}: SecurityHubIntegrationsManagerProps) => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingIntegration, setEditingIntegration] =
    useState<IntegrationProps | null>(null);
  const [editMode, setEditMode] = useState<
    "configuration" | "credentials" | null
  >(null);
  const [isDeleting, setIsDeleting] = useState<string | null>(null);
  const [isTesting, setIsTesting] = useState<string | null>(null);
  const [isOperationLoading, setIsOperationLoading] = useState(false);
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const [integrationToDelete, setIntegrationToDelete] =
    useState<IntegrationProps | null>(null);
  const { toast } = useToast();

  const handleAddIntegration = () => {
    setEditingIntegration(null);
    setEditMode(null);
    setIsModalOpen(true);
  };

  const handleEditConfiguration = (integration: IntegrationProps) => {
    setEditingIntegration(integration);
    setEditMode("configuration");
    setIsModalOpen(true);
  };

  const handleEditCredentials = (integration: IntegrationProps) => {
    setEditingIntegration(integration);
    setEditMode("credentials");
    setIsModalOpen(true);
  };

  const handleOpenDeleteModal = (integration: IntegrationProps) => {
    setIntegrationToDelete(integration);
    setIsDeleteOpen(true);
  };

  const handleDeleteIntegration = async (id: string) => {
    setIsDeleting(id);
    try {
      const result = await deleteIntegration(id, "aws_security_hub");

      if (result.success) {
        toast({
          title: "Success!",
          description: "Security Hub integration deleted successfully.",
        });
      } else if (result.error) {
        toast({
          variant: "destructive",
          title: "Delete Failed",
          description: result.error,
        });
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description:
          "Failed to delete Security Hub integration. Please try again.",
      });
    } finally {
      setIsDeleting(null);
      setIsDeleteOpen(false);
      setIntegrationToDelete(null);
    }
  };

  const handleTestConnection = async (id: string) => {
    setIsTesting(id);
    try {
      const result = await testIntegrationConnection(id);

      if (result.success) {
        toast({
          title: "Connection test successful!",
          description:
            result.message || "Connection test completed successfully.",
        });
      } else if (result.error) {
        toast({
          variant: "destructive",
          title: "Connection test failed",
          description: result.error,
        });
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to test connection. Please try again.",
      });
    } finally {
      setIsTesting(null);
    }
  };

  const handleToggleEnabled = async (integration: IntegrationProps) => {
    try {
      const newEnabledState = !integration.attributes.enabled;
      const formData = new FormData();
      formData.append(
        "integration_type",
        integration.attributes.integration_type,
      );
      formData.append("enabled", JSON.stringify(newEnabledState));

      const result = await updateIntegration(integration.id, formData);

      if (result && "success" in result) {
        toast({
          title: "Success!",
          description: `Integration ${newEnabledState ? "enabled" : "disabled"} successfully.`,
        });
      } else if (result && "error" in result) {
        toast({
          variant: "destructive",
          title: "Toggle Failed",
          description: result.error,
        });
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to toggle integration. Please try again.",
      });
    }
  };

  const handleModalClose = () => {
    setIsModalOpen(false);
    setEditingIntegration(null);
    setEditMode(null);
  };

  const handleFormSuccess = () => {
    setIsModalOpen(false);
    setEditingIntegration(null);
    setEditMode(null);
    setIsOperationLoading(true);
    setTimeout(() => {
      setIsOperationLoading(false);
    }, 1500);
  };

  const getProviderDetails = (integration: IntegrationProps) => {
    const providerRelationships = integration.relationships?.providers?.data;

    if (!providerRelationships || providerRelationships.length === 0) {
      return { displayName: "Unknown Account", accountId: null };
    }

    // Security Hub should only have one provider
    const providerId = providerRelationships[0].id;
    const provider = providers.find((p) => p.id === providerId);

    if (!provider) {
      return { displayName: "Unknown Account", accountId: null };
    }

    return {
      displayName: provider.attributes.alias || provider.attributes.uid,
      accountId: provider.attributes.uid,
      alias: provider.attributes.alias,
    };
  };

  const getEnabledRegions = (integration: IntegrationProps) => {
    const regions = integration.attributes.configuration.regions;
    if (!regions || typeof regions !== "object") return [];

    return Object.entries(regions)
      .filter(([_, enabled]) => enabled === true)
      .map(([region]) => region)
      .sort();
  };

  return (
    <>
      <CustomAlertModal
        isOpen={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Delete Security Hub Integration"
        description="This action cannot be undone. This will permanently delete your Security Hub integration."
      >
        <div className="flex w-full justify-center space-x-6">
          <CustomButton
            type="button"
            ariaLabel="Cancel"
            className="w-full bg-transparent"
            variant="faded"
            size="lg"
            onPress={() => {
              setIsDeleteOpen(false);
              setIntegrationToDelete(null);
            }}
            isDisabled={isDeleting !== null}
          >
            <span>Cancel</span>
          </CustomButton>

          <CustomButton
            type="button"
            ariaLabel="Delete"
            className="w-full"
            variant="solid"
            color="danger"
            size="lg"
            isLoading={isDeleting !== null}
            startContent={!isDeleting && <Trash2Icon size={24} />}
            onPress={() =>
              integrationToDelete &&
              handleDeleteIntegration(integrationToDelete.id)
            }
          >
            {isDeleting ? "Deleting..." : "Delete"}
          </CustomButton>
        </div>
      </CustomAlertModal>

      <CustomAlertModal
        isOpen={isModalOpen}
        onOpenChange={setIsModalOpen}
        title={
          editMode === "configuration"
            ? "Edit Configuration"
            : editMode === "credentials"
              ? "Edit Credentials"
              : editingIntegration
                ? "Edit Security Hub Integration"
                : "Add Security Hub Integration"
        }
      >
        <SecurityHubIntegrationForm
          integration={editingIntegration}
          providers={providers}
          existingIntegrations={integrations}
          onSuccess={handleFormSuccess}
          onCancel={handleModalClose}
          editMode={editMode}
        />
      </CustomAlertModal>

      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold">
              Configured Security Hub Integrations
            </h3>
            <p className="text-sm text-gray-500 dark:text-gray-300">
              {integrations.length === 0
                ? "Not configured yet"
                : `${integrations.length} integration${integrations.length !== 1 ? "s" : ""} configured`}
            </p>
          </div>
          <CustomButton
            color="action"
            startContent={<PlusIcon size={16} />}
            onPress={handleAddIntegration}
            ariaLabel="Add integration"
          >
            Add Integration
          </CustomButton>
        </div>

        {isOperationLoading ? (
          <SecurityHubIntegrationCardSkeleton
            variant="manager"
            count={integrations.length || 1}
          />
        ) : integrations.length > 0 ? (
          <div className="grid gap-4">
            {integrations.map((integration) => {
              const enabledRegions = getEnabledRegions(integration);
              const providerDetails = getProviderDetails(integration);

              return (
                <Card key={integration.id} className="dark:bg-gray-800">
                  <CardHeader className="pb-2">
                    <div className="flex w-full items-center justify-between">
                      <div className="flex items-center gap-3">
                        <AWSSecurityHubIcon size={32} />
                        <div>
                          <h4 className="text-md font-semibold">
                            {providerDetails.displayName}
                          </h4>
                          <p className="text-xs text-gray-500 dark:text-gray-300">
                            {providerDetails.accountId && providerDetails.alias
                              ? `Account ID: ${providerDetails.accountId}`
                              : "AWS Security Hub Integration"}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Chip
                          size="sm"
                          variant="flat"
                          color="default"
                          className="text-xs"
                        >
                          {integration.attributes.configuration.send_only_fails
                            ? "Failed Only"
                            : "All Findings"}
                        </Chip>
                        <Chip
                          size="sm"
                          variant="flat"
                          color="default"
                          className="text-xs"
                        >
                          {integration.attributes.configuration
                            .archive_previous_findings
                            ? "Archive Previous"
                            : "Keep Previous"}
                        </Chip>
                        <Chip
                          size="sm"
                          color={
                            integration.attributes.connected
                              ? "success"
                              : "danger"
                          }
                          variant="flat"
                        >
                          {integration.attributes.connected
                            ? "Connected"
                            : "Disconnected"}
                        </Chip>
                      </div>
                    </div>
                  </CardHeader>
                  <CardBody className="pt-0">
                    <div className="flex flex-col gap-3">
                      {enabledRegions.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {enabledRegions.map((region) => (
                            <Chip
                              key={region}
                              size="sm"
                              variant="flat"
                              className="bg-default-100"
                            >
                              {region}
                            </Chip>
                          ))}
                        </div>
                      )}

                      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                        <div className="text-xs text-gray-500 dark:text-gray-300">
                          {integration.attributes.updated_at && (
                            <p>
                              <span className="font-medium">Last updated:</span>{" "}
                              {format(
                                new Date(integration.attributes.updated_at),
                                "yyyy/MM/dd",
                              )}
                            </p>
                          )}
                        </div>
                        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                          <CustomButton
                            size="sm"
                            variant="bordered"
                            startContent={<TestTube size={14} />}
                            onPress={() => handleTestConnection(integration.id)}
                            isLoading={isTesting === integration.id}
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
                            onPress={() => handleEditConfiguration(integration)}
                            ariaLabel="Edit configuration"
                            className="w-full sm:w-auto"
                          >
                            Config
                          </CustomButton>
                          <CustomButton
                            size="sm"
                            variant="bordered"
                            startContent={<SettingsIcon size={14} />}
                            onPress={() => handleEditCredentials(integration)}
                            ariaLabel="Edit credentials"
                            className="w-full sm:w-auto"
                          >
                            Credentials
                          </CustomButton>
                          <CustomButton
                            size="sm"
                            variant="bordered"
                            color={
                              integration.attributes.enabled
                                ? "warning"
                                : "primary"
                            }
                            startContent={<Power size={14} />}
                            onPress={() => handleToggleEnabled(integration)}
                            ariaLabel={
                              integration.attributes.enabled
                                ? "Disable integration"
                                : "Enable integration"
                            }
                            className="w-full sm:w-auto"
                          >
                            {integration.attributes.enabled
                              ? "Disable"
                              : "Enable"}
                          </CustomButton>
                          <CustomButton
                            size="sm"
                            color="danger"
                            variant="bordered"
                            startContent={<Trash2Icon size={14} />}
                            onPress={() => handleOpenDeleteModal(integration)}
                            ariaLabel="Delete integration"
                            className="w-full sm:w-auto"
                          >
                            Delete
                          </CustomButton>
                        </div>
                      </div>
                    </div>
                  </CardBody>
                </Card>
              );
            })}
          </div>
        ) : null}

        {metadata && integrations.length > 0 && (
          <div className="mt-6">
            <DataTablePagination metadata={metadata} />
          </div>
        )}
      </div>
    </>
  );
};
