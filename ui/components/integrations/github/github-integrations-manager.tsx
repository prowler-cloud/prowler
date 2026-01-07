"use client";

import { format } from "date-fns";
import { GithubIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import {
  deleteIntegration,
  testIntegrationConnection,
  updateIntegration,
} from "@/actions/integrations";
import {
  IntegrationActionButtons,
  IntegrationCardHeader,
  IntegrationSkeleton,
} from "@/components/integrations/shared";
import { Button } from "@/components/shadcn";
import { useToast } from "@/components/ui";
import { CustomAlertModal } from "@/components/ui/custom";
import { DataTablePagination } from "@/components/ui/table/data-table-pagination";
import { triggerTestConnectionWithDelay } from "@/lib/integrations/test-connection-helper";
import { MetaDataProps } from "@/types";
import { IntegrationProps } from "@/types/integrations";

import { Card, CardContent, CardHeader } from "../../shadcn";
import { GitHubIntegrationForm } from "./github-integration-form";

interface GitHubIntegrationsManagerProps {
  integrations: IntegrationProps[];
  metadata?: MetaDataProps;
}

export const GitHubIntegrationsManager = ({
  integrations,
  metadata,
}: GitHubIntegrationsManagerProps) => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingIntegration, setEditingIntegration] =
    useState<IntegrationProps | null>(null);
  const [isDeleting, setIsDeleting] = useState<string | null>(null);
  const [isTesting, setIsTesting] = useState<string | null>(null);
  const [isOperationLoading, setIsOperationLoading] = useState(false);
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const [integrationToDelete, setIntegrationToDelete] =
    useState<IntegrationProps | null>(null);
  const { toast } = useToast();

  const handleAddIntegration = () => {
    setEditingIntegration(null);
    setIsModalOpen(true);
  };

  const handleEditCredentials = (integration: IntegrationProps) => {
    setEditingIntegration(integration);
    setIsModalOpen(true);
  };

  const handleOpenDeleteModal = (integration: IntegrationProps) => {
    setIntegrationToDelete(integration);
    setIsDeleteOpen(true);
  };

  const handleDeleteIntegration = async (id: string) => {
    setIsDeleting(id);
    try {
      const result = await deleteIntegration(id, "github");

      if (result.success) {
        toast({
          title: "Success!",
          description: "GitHub integration deleted successfully.",
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
        description: "Failed to delete GitHub integration. Please try again.",
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

        // If enabling, trigger test connection automatically
        if (newEnabledState) {
          setIsTesting(integration.id);

          triggerTestConnectionWithDelay(
            integration.id,
            true,
            "github",
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
  };

  const handleFormSuccess = async (
    integrationId?: string,
    shouldTestConnection?: boolean,
  ) => {
    // Close the modal immediately
    setIsModalOpen(false);
    setEditingIntegration(null);
    setIsOperationLoading(true);

    // Set testing state for server-triggered test connections
    if (integrationId && shouldTestConnection) {
      setIsTesting(integrationId);
    }

    // Trigger test connection if needed
    triggerTestConnectionWithDelay(
      integrationId,
      shouldTestConnection,
      "github",
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

  return (
    <>
      <CustomAlertModal
        isOpen={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Delete GitHub Integration"
        description="This action cannot be undone. This will permanently delete your GitHub integration."
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
      </CustomAlertModal>

      <CustomAlertModal
        isOpen={isModalOpen}
        onOpenChange={handleModalClose}
        title={
          editingIntegration ? "Edit GitHub Integration" : "Add GitHub Integration"
        }
        description={
          editingIntegration
            ? "Update the credentials for your GitHub integration."
            : "Configure your GitHub Personal Access Token to create issues from findings."
        }
      >
        <GitHubIntegrationForm
          integration={editingIntegration}
          onSuccess={handleFormSuccess}
          onCancel={handleModalClose}
        />
      </CustomAlertModal>

      <div className="space-y-6">
        <div className="flex w-full flex-col items-start gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-2xl font-bold">GitHub Integrations</h2>
            <p className="text-default-500 text-sm">
              Manage your GitHub integrations to send findings as issues
            </p>
          </div>
          <Button onClick={handleAddIntegration} size="sm">
            <PlusIcon size={20} />
            Add Integration
          </Button>
        </div>

        <div className="flex flex-col gap-4">
          {isOperationLoading && <IntegrationSkeleton />}
          {!isOperationLoading && integrations.length === 0 && (
            <Card variant="base" padding="lg">
              <CardContent className="flex flex-col items-center justify-center py-12">
                <GithubIcon
                  size={48}
                  className="mb-4 text-gray-400 dark:text-gray-600"
                />
                <h3 className="mb-2 text-lg font-semibold text-gray-900 dark:text-gray-100">
                  No GitHub integrations configured
                </h3>
                <p className="mb-4 text-center text-sm text-gray-500 dark:text-gray-400">
                  Get started by adding your first GitHub integration
                </p>
                <Button onClick={handleAddIntegration} size="sm">
                  <PlusIcon size={16} />
                  Add Integration
                </Button>
              </CardContent>
            </Card>
          )}
          {!isOperationLoading &&
            integrations.map((integration) => (
              <Card key={integration.id} variant="base" padding="lg">
                <CardHeader>
                  <IntegrationCardHeader
                    icon={
                      <GithubIcon
                        size={32}
                        className="text-gray-900 dark:text-gray-100"
                      />
                    }
                    title="GitHub Integration"
                    subtitle={
                      integration.attributes.configuration.owner
                        ? `Owner: ${integration.attributes.configuration.owner}`
                        : "All accessible repositories"
                    }
                    integrationId={integration.id}
                    enabled={integration.attributes.enabled}
                    connected={integration.attributes.connected}
                    lastChecked={integration.attributes.connection_last_checked_at}
                    isTesting={isTesting === integration.id}
                  />
                </CardHeader>
                <CardContent>
                  <div className="flex flex-col gap-4">
                    {integration.attributes.configuration.repositories &&
                      Object.keys(
                        integration.attributes.configuration.repositories,
                      ).length > 0 && (
                        <div>
                          <p className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-300">
                            Accessible Repositories:{" "}
                            {
                              Object.keys(
                                integration.attributes.configuration.repositories,
                              ).length
                            }
                          </p>
                          <p className="text-xs text-gray-500 dark:text-gray-400">
                            Last synced:{" "}
                            {integration.attributes.connection_last_checked_at
                              ? format(
                                  new Date(
                                    integration.attributes.connection_last_checked_at,
                                  ),
                                  "PPpp",
                                )
                              : "Never"}
                          </p>
                        </div>
                      )}

                    <IntegrationActionButtons
                      integration={integration}
                      isTesting={isTesting === integration.id}
                      isDeleting={isDeleting === integration.id}
                      onTestConnection={handleTestConnection}
                      onToggleEnabled={handleToggleEnabled}
                      onEditCredentials={handleEditCredentials}
                      onDelete={handleOpenDeleteModal}
                    />
                  </div>
                </CardContent>
              </Card>
            ))}
        </div>

        {metadata && integrations.length > 0 && !isOperationLoading && (
          <DataTablePagination metadata={metadata} />
        )}
      </div>
    </>
  );
};
