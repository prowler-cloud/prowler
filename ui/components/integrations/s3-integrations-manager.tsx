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

import { S3IntegrationForm } from "./forms";

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
  const [isDeleting, setIsDeleting] = useState<string | null>(null);
  const [isTesting, setIsTesting] = useState<string | null>(null);
  const { toast } = useToast();

  const handleAddIntegration = () => {
    setEditingIntegration(null);
    setIsModalOpen(true);
  };

  const handleEditIntegration = (integration: IntegrationProps) => {
    setEditingIntegration(integration);
    setIsModalOpen(true);
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
        // No need for manual reload, revalidatePath handles it
      } else if (result.errors?.general) {
        toast({
          variant: "destructive",
          title: "Error",
          description: result.errors.general,
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
    }
  };

  const handleTestConnection = async (id: string) => {
    setIsTesting(id);
    try {
      const result = await testIntegrationConnection(id);

      if (result.success) {
        toast({
          title: "Success!",
          description: "Connection test started successfully.",
        });
      } else if (result.errors?.general) {
        toast({
          variant: "destructive",
          title: "Error",
          description: result.errors.general,
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
  };

  const handleFormSuccess = () => {
    setIsModalOpen(false);
    setEditingIntegration(null);
    // No need for manual reload, revalidatePath handles it
  };

  return (
    <>
      <CustomAlertModal
        isOpen={isModalOpen}
        onOpenChange={setIsModalOpen}
        title={
          editingIntegration ? "Edit S3 Integration" : "Add S3 Integration"
        }
      >
        <S3IntegrationForm
          integration={editingIntegration}
          providers={providers}
          onSuccess={handleFormSuccess}
          onCancel={handleModalClose}
        />
      </CustomAlertModal>

      <div className="space-y-6">
        {/* Header with Add Button */}
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold">
              Configured S3 Integrations
            </h3>
            <p className="text-sm text-gray-500">
              {integrations.length === 0
                ? "Not configured yet"
                : `${integrations.length} integration${integrations.length !== 1 ? "s" : ""} configured.`}
            </p>
          </div>
          <CustomButton
            color="action"
            startContent={<PlusIcon size={16} />}
            onPress={handleAddIntegration}
            ariaLabel="Add new S3 integration"
          >
            Add S3 Integration
          </CustomButton>
        </div>

        {/* Integrations List */}
        {integrations.length > 0 && (
          <div className="grid gap-4">
            {integrations.map((integration) => (
              <Card key={integration.id} className="dark:bg-prowler-blue-400">
                <CardHeader className="pb-2">
                  <div className="flex w-full items-center justify-between">
                    <div className="flex items-center gap-3">
                      <AmazonS3Icon size={32} />
                      <div>
                        <h4 className="text-md font-semibold">
                          {integration.attributes.configuration.bucket_name ||
                            "Unknown Bucket"}
                        </h4>
                        <p className="text-xs text-gray-500">
                          Output Directory:{" "}
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
                  <div className="flex items-center justify-between">
                    <div className="text-xs text-gray-500">
                      <p>
                        <span className="font-medium">Auth:</span>{" "}
                        {integration.attributes.configuration.credentials
                          ?.role_arn
                          ? "IAM Role + Static Credentials"
                          : "Static Credentials"}
                      </p>
                      {integration.attributes.connection_last_checked_at && (
                        <p>
                          <span className="font-medium">Last checked:</span>{" "}
                          {new Date(
                            integration.attributes.connection_last_checked_at,
                          ).toLocaleDateString()}
                        </p>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <CustomButton
                        size="sm"
                        variant="bordered"
                        startContent={<TestTube size={14} />}
                        onPress={() => handleTestConnection(integration.id)}
                        isLoading={isTesting === integration.id}
                        ariaLabel="Test connection"
                      >
                        Test
                      </CustomButton>
                      <CustomButton
                        size="sm"
                        variant="bordered"
                        startContent={<SettingsIcon size={14} />}
                        onPress={() => handleEditIntegration(integration)}
                        ariaLabel="Edit integration"
                      >
                        Edit
                      </CustomButton>
                      <CustomButton
                        size="sm"
                        color="danger"
                        variant="bordered"
                        startContent={<Trash2Icon size={14} />}
                        onPress={() => handleDeleteIntegration(integration.id)}
                        isLoading={isDeleting === integration.id}
                        ariaLabel="Delete integration"
                      >
                        Delete
                      </CustomButton>
                    </div>
                  </div>
                </CardBody>
              </Card>
            ))}
          </div>
        )}
      </div>
    </>
  );
};
