"use client";

import { format } from "date-fns";
import { MailIcon, PlusIcon, Trash2Icon } from "lucide-react";
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
import { SNSIntegrationForm } from "./sns-integration-form";

interface SNSIntegrationsManagerProps {
  integrations: IntegrationProps[];
  metadata?: MetaDataProps;
}

export const SNSIntegrationsManager = ({
  integrations,
  metadata,
}: SNSIntegrationsManagerProps) => {
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
      const result = await deleteIntegration(id, "sns");

      if (result.success) {
        toast({
          title: "Success!",
          description: "SNS integration deleted successfully.",
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
        description: "Failed to delete SNS integration. Please try again.",
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
            "sns",
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
      "sns",
      toast,
      200,
      () => {
        // Clear testing state when server-triggered test completes
        setIsTesting(null);
        setIsOperationLoading(false);
      },
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100">
            Manage SNS Integrations
          </h2>
          <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">
            Configure Amazon SNS topics to send email alerts for security
            findings
          </p>
        </div>
        <Button onClick={handleAddIntegration}>
          <PlusIcon size={16} />
          Add Integration
        </Button>
      </div>

      <div className="grid gap-4">
        {integrations.length === 0 ? (
          <Card variant="base" padding="lg">
            <CardContent>
              <div className="flex flex-col items-center justify-center py-12">
                <MailIcon size={48} className="mb-4 text-gray-400" />
                <h3 className="mb-2 text-lg font-semibold text-gray-900 dark:text-gray-100">
                  No SNS integrations configured
                </h3>
                <p className="mb-4 text-center text-sm text-gray-600 dark:text-gray-300">
                  Add your first SNS integration to start sending email alerts
                  for security findings
                </p>
                <Button onClick={handleAddIntegration}>
                  <PlusIcon size={16} />
                  Add Integration
                </Button>
              </div>
            </CardContent>
          </Card>
        ) : (
          <>
            {integrations.map((integration) => (
              <Card key={integration.id} variant="base" padding="lg">
                <CardHeader>
                  <IntegrationCardHeader
                    integration={integration}
                    icon={
                      <MailIcon
                        size={24}
                        className="text-orange-600 dark:text-orange-400"
                      />
                    }
                    title="Amazon SNS Integration"
                    onToggle={() => handleToggleEnabled(integration)}
                    isTesting={isTesting === integration.id}
                  />
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="grid gap-4 sm:grid-cols-2">
                      <div>
                        <p className="text-xs font-medium text-gray-500 dark:text-gray-400">
                          SNS Topic ARN
                        </p>
                        <p className="mt-1 text-sm text-gray-900 dark:text-gray-100">
                          {integration.attributes.configuration.topic_arn ||
                            "Not configured"}
                        </p>
                      </div>
                      <div>
                        <p className="text-xs font-medium text-gray-500 dark:text-gray-400">
                          Last Checked
                        </p>
                        <p className="mt-1 text-sm text-gray-900 dark:text-gray-100">
                          {integration.attributes.connection_last_checked_at
                            ? format(
                                new Date(
                                  integration.attributes
                                    .connection_last_checked_at,
                                ),
                                "MMM d, yyyy HH:mm",
                              )
                            : "Never"}
                        </p>
                      </div>
                    </div>

                    <IntegrationActionButtons
                      integration={integration}
                      onTestConnection={() =>
                        handleTestConnection(integration.id)
                      }
                      onEditConfiguration={() =>
                        handleEditConfiguration(integration)
                      }
                      onEditCredentials={() =>
                        handleEditCredentials(integration)
                      }
                      onDelete={() => handleOpenDeleteModal(integration)}
                      isTesting={isTesting === integration.id}
                      isDeleting={isDeleting === integration.id}
                    />
                  </div>
                </CardContent>
              </Card>
            ))}

            {metadata && (
              <DataTablePagination
                currentPage={metadata.page.currentPage}
                totalPages={metadata.page.totalPages}
                pageSize={metadata.page.pageSize}
                totalCount={metadata.page.totalCount}
              />
            )}
          </>
        )}
      </div>

      {/* Add/Edit Modal */}
      <CustomAlertModal
        isOpen={isModalOpen}
        onClose={handleModalClose}
        title={
          editingIntegration
            ? editMode === "configuration"
              ? "Edit SNS Configuration"
              : "Edit AWS Credentials"
            : "Add SNS Integration"
        }
        maxWidth="2xl"
      >
        <SNSIntegrationForm
          integration={editingIntegration}
          editMode={editMode}
          onSuccess={handleFormSuccess}
          onCancel={handleModalClose}
        />
      </CustomAlertModal>

      {/* Delete Confirmation Modal */}
      <CustomAlertModal
        isOpen={isDeleteOpen}
        onClose={() => setIsDeleteOpen(false)}
        title="Delete SNS Integration"
        description="Are you sure you want to delete this SNS integration? This action cannot be undone."
        maxWidth="md"
      >
        <div className="mt-4 flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setIsDeleteOpen(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={() =>
              integrationToDelete &&
              handleDeleteIntegration(integrationToDelete.id)
            }
            disabled={!!isDeleting}
          >
            {isDeleting ? (
              <>
                <IntegrationSkeleton />
                Deleting...
              </>
            ) : (
              <>
                <Trash2Icon size={16} />
                Delete
              </>
            )}
          </Button>
        </div>
      </CustomAlertModal>
    </div>
  );
};
