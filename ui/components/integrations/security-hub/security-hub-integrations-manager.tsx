"use client";

import { Chip } from "@heroui/chip";
import { format } from "date-fns";
import { PlusIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import {
  deleteIntegration,
  testIntegrationConnection,
  updateIntegration,
} from "@/actions/integrations";
import { AWSSecurityHubIcon } from "@/components/icons/services/IconServices";
import {
  IntegrationActionButtons,
  IntegrationCardHeader,
  IntegrationSkeleton,
} from "@/components/integrations/shared";
import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/ui";
import { DataTablePagination } from "@/components/ui/table/data-table-pagination";
import { triggerTestConnectionWithDelay } from "@/lib/integrations/test-connection-helper";
import { MetaDataProps } from "@/types";
import { IntegrationProps } from "@/types/integrations";
import { ProviderProps } from "@/types/providers";

import { Card, CardContent, CardHeader } from "../../shadcn";
import { SecurityHubIntegrationForm } from "./security-hub-integration-form";

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
    } catch (_error) {
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
    } catch (_error) {
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

        // If enabling, trigger test connection automatically
        if (newEnabledState) {
          setIsTesting(integration.id);

          triggerTestConnectionWithDelay(
            integration.id,
            true,
            "security_hub",
            toast,
            500,
            () => {
              setIsTesting(null);
            },
          );
        }
      } else if (result && "error" in result) {
        toast({
          variant: "destructive",
          title: "Toggle Failed",
          description: result.error,
        });
      }
    } catch (_error) {
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

  const handleFormSuccess = async (
    integrationId?: string,
    shouldTestConnection?: boolean,
  ) => {
    // Close the modal immediately
    setIsModalOpen(false);
    setEditingIntegration(null);
    setEditMode(null);
    setIsOperationLoading(true);

    // Set testing state for server-triggered test connections
    if (integrationId && shouldTestConnection) {
      setIsTesting(integrationId);
    }

    // Trigger test connection if needed
    triggerTestConnectionWithDelay(
      integrationId,
      shouldTestConnection,
      "security_hub",
      toast,
      200,
      () => {
        // Clear testing state when server-triggered test completes
        setIsTesting(null);
      },
    );

    // Reset loading state after a short delay to show the skeleton briefly
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
      <Modal
        open={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Delete Security Hub Integration"
        description="This action cannot be undone. This will permanently delete your Security Hub integration."
      >
        <div className="flex w-full justify-end gap-4">
          <Button
            type="button"
            variant="ghost"
            size="lg"
            onClick={() => {
              setIsDeleteOpen(false);
              setIntegrationToDelete(null);
            }}
            disabled={isDeleting !== null}
          >
            Cancel
          </Button>

          <Button
            type="button"
            variant="destructive"
            size="lg"
            disabled={isDeleting !== null}
            onClick={() =>
              integrationToDelete &&
              handleDeleteIntegration(integrationToDelete.id)
            }
          >
            {!isDeleting && <Trash2Icon size={24} />}
            {isDeleting ? "Deleting..." : "Delete"}
          </Button>
        </div>
      </Modal>

      <Modal
        open={isModalOpen}
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
      </Modal>

      <div className="flex flex-col gap-6">
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
          <Button onClick={handleAddIntegration}>
            <PlusIcon size={16} />
            Add Integration
          </Button>
        </div>

        {isOperationLoading ? (
          <IntegrationSkeleton
            variant="manager"
            count={integrations.length || 1}
            icon={<AWSSecurityHubIcon size={32} />}
            title="AWS Security Hub"
            subtitle="Send security findings to AWS Security Hub."
          />
        ) : integrations.length > 0 ? (
          <div className="grid gap-4">
            {integrations.map((integration) => {
              const enabledRegions = getEnabledRegions(integration);
              const providerDetails = getProviderDetails(integration);

              return (
                <Card key={integration.id} variant="base">
                  <CardHeader>
                    <IntegrationCardHeader
                      icon={<AWSSecurityHubIcon size={32} />}
                      title={providerDetails.displayName}
                      subtitle={
                        providerDetails.accountId && providerDetails.alias
                          ? `Account ID: ${providerDetails.accountId}`
                          : "AWS Security Hub Integration"
                      }
                      chips={[
                        {
                          label: integration.attributes.configuration
                            .send_only_fails
                            ? "Failed Only"
                            : "All Findings",
                        },
                        {
                          label: integration.attributes.configuration
                            .archive_previous_findings
                            ? "Archive Previous"
                            : "Keep Previous",
                        },
                      ]}
                      connectionStatus={{
                        connected: integration.attributes.connected,
                      }}
                    />
                  </CardHeader>
                  <CardContent className="pt-0">
                    <div className="flex flex-col gap-3">
                      {enabledRegions.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {enabledRegions.map((region) => (
                            <Chip
                              key={region}
                              size="sm"
                              variant="flat"
                              className="bg-bg-neutral-secondary"
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
                        <IntegrationActionButtons
                          integration={integration}
                          onTestConnection={handleTestConnection}
                          onEditConfiguration={handleEditConfiguration}
                          onEditCredentials={handleEditCredentials}
                          onToggleEnabled={handleToggleEnabled}
                          onDelete={handleOpenDeleteModal}
                          isTesting={isTesting === integration.id}
                        />
                      </div>
                    </div>
                  </CardContent>
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
