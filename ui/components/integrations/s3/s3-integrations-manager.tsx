"use client";

import { Card, CardBody, CardHeader, Chip } from "@nextui-org/react";
import { PlusIcon, SettingsIcon, TestTube, Trash2Icon } from "lucide-react";
import { useState } from "react";

import {
  deleteIntegration,
  testIntegrationConnection,
} from "@/actions/integrations";
import { AmazonS3Icon } from "@/components/icons/services/IconServices";
import { useToast } from "@/components/ui";
import { CustomAlertModal, CustomButton } from "@/components/ui/custom";
import { IntegrationProps } from "@/types/integrations";
import { ProviderProps } from "@/types/providers";

import { S3IntegrationForm } from "./s3-integration-form";
import { S3IntegrationCardSkeleton } from "./skeleton-s3-integration-card";

interface S3IntegrationsManagerProps {
  integrations: IntegrationProps[];
  providers: ProviderProps[];
}

export const S3IntegrationsManager = ({
  integrations,
  providers,
}: S3IntegrationsManagerProps) => {
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
    setEditMode(null); // Creation mode
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
      const result = await deleteIntegration(id);

      if (result.success) {
        toast({
          title: "Success!",
          description: "S3 integration deleted successfully.",
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
        description: "Failed to delete S3 integration. Please try again.",
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
          title: "Connection Test Successful!",
          description:
            result.message || "Connection test completed successfully.",
        });
      } else if (result.error) {
        toast({
          variant: "destructive",
          title: "Connection Test Failed",
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
        title="Delete S3 Integration"
        description="This action cannot be undone. This will permanently delete your S3 integration."
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
                ? "Edit S3 Integration"
                : "Add S3 Integration"
        }
      >
        <S3IntegrationForm
          integration={editingIntegration}
          providers={providers}
          onSuccess={handleFormSuccess}
          onCancel={handleModalClose}
          editMode={editMode}
        />
      </CustomAlertModal>

      <div className="space-y-6">
        {/* Header with Add Button */}
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold">
              Configured S3 Integrations
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

        {/* Integrations List */}
        {isOperationLoading ? (
          <S3IntegrationCardSkeleton
            variant="manager"
            count={integrations.length || 1}
          />
        ) : integrations.length > 0 ? (
          <div className="grid gap-4">
            {integrations.map((integration) => (
              <Card key={integration.id} className="dark:bg-gray-800">
                <CardHeader className="pb-2">
                  <div className="flex w-full items-center justify-between">
                    <div className="flex items-center gap-3">
                      <AmazonS3Icon size={32} />
                      <div>
                        <h4 className="text-md font-semibold">
                          {integration.attributes.configuration.bucket_name ||
                            "Unknown Bucket"}
                        </h4>
                        <p className="text-xs text-gray-500 dark:text-gray-300">
                          Output directory:{" "}
                          {integration.attributes.configuration
                            .output_directory ||
                            integration.attributes.configuration.path ||
                            "/"}
                        </p>
                      </div>
                    </div>
                    <Chip
                      size="sm"
                      color={
                        integration.attributes.connected ? "success" : "danger"
                      }
                      variant="flat"
                    >
                      {integration.attributes.connected
                        ? "Connected"
                        : "Disconnected"}
                    </Chip>
                  </div>
                </CardHeader>
                <CardBody className="pt-0">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div className="text-xs text-gray-500 dark:text-gray-300">
                      {integration.attributes.connection_last_checked_at && (
                        <p>
                          <span className="font-medium">Last checked:</span>{" "}
                          {new Date(
                            integration.attributes.connection_last_checked_at,
                          ).toLocaleDateString()}
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
                </CardBody>
              </Card>
            ))}
          </div>
        ) : null}
      </div>
    </>
  );
};
