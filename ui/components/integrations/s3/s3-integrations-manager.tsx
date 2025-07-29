"use client";

import { Card, CardBody, CardHeader, Chip } from "@nextui-org/react";
import { PlusIcon, SettingsIcon, TestTube, Trash2Icon } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import {
  deleteIntegration,
  testIntegrationConnection,
} from "@/actions/integrations";
import { getTask } from "@/actions/task/tasks";
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
  const { toast } = useToast();

  // Store polling intervals to clean them up
  const pollingIntervalsRef = useRef<Map<string, NodeJS.Timeout>>(new Map());

  // Cleanup intervals on unmount
  useEffect(() => {
    const intervals = pollingIntervalsRef.current;
    return () => {
      intervals.forEach((interval) => {
        clearInterval(interval);
      });
      intervals.clear();
    };
  }, []);

  const pollTaskStatus = async (taskId: string, _integrationId: string) => {
    const pollInterval = setInterval(async () => {
      try {
        const taskResponse = await getTask(taskId);

        if (taskResponse.error) {
          clearInterval(pollInterval);
          pollingIntervalsRef.current.delete(taskId);
          setIsTesting(null);
          toast({
            variant: "destructive",
            title: "Error",
            description: taskResponse.error,
          });
          return;
        }

        const task = taskResponse.data;
        const taskState = task?.attributes?.state;

        // Continue polling while task is executing
        if (
          taskState === "executing" ||
          taskState === "scheduled" ||
          taskState === "available"
        ) {
          return;
        }

        // Task has finished, stop polling
        clearInterval(pollInterval);
        pollingIntervalsRef.current.delete(taskId);
        setIsTesting(null);

        // Show result based on final state
        if (taskState === "completed") {
          const result = task?.attributes?.result;
          const isSuccessful =
            result?.success === true || result?.status === "success";

          if (isSuccessful) {
            toast({
              title: "Connection Test Successful!",
              description:
                result?.message || "Connection test completed successfully.",
            });
          } else {
            toast({
              variant: "destructive",
              title: "Connection Test Failed",
              description:
                result?.message || result?.error || "Connection test failed.",
            });
          }
        } else if (taskState === "failed") {
          const result = task?.attributes?.result;
          toast({
            variant: "destructive",
            title: "Connection Test Failed",
            description:
              result?.message || result?.error || "Task failed to complete.",
          });
        } else if (taskState === "cancelled") {
          const result = task?.attributes?.result;
          toast({
            variant: "destructive",
            title: "Connection Test Cancelled",
            description:
              result?.message || "The connection test was cancelled.",
          });
        } else {
          // Unknown state
          const result = task?.attributes?.result;
          toast({
            variant: "destructive",
            title: "Connection Test Completed",
            description:
              result?.message || `Task completed with state: ${taskState}`,
          });
        }
      } catch (error) {
        clearInterval(pollInterval);
        pollingIntervalsRef.current.delete(taskId);
        setIsTesting(null);
        toast({
          variant: "destructive",
          title: "Error",
          description: "Failed to monitor connection test. Please try again.",
        });
      }
    }, 2000); // Poll every 2 seconds

    // Store the interval for cleanup
    pollingIntervalsRef.current.set(taskId, pollInterval);

    // Set a maximum timeout to avoid infinite polling (5 minutes)
    setTimeout(() => {
      if (pollingIntervalsRef.current.has(taskId)) {
        clearInterval(pollInterval);
        pollingIntervalsRef.current.delete(taskId);
        setIsTesting(null);
        toast({
          variant: "destructive",
          title: "Connection Test Timeout",
          description: "Connection test took too long to complete.",
        });
      }
    }, 300000); // 5 minutes timeout
  };

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
    }
  };

  const handleTestConnection = async (id: string) => {
    setIsTesting(id);
    try {
      const result = await testIntegrationConnection(id);

      if (result.success) {
        const taskId = result.data?.data?.id;

        if (taskId) {
          // Start polling the task status
          await pollTaskStatus(taskId, id);

          toast({
            title: "Connection Test Started",
            description:
              "Connection test is running. You'll be notified when it completes.",
          });
        } else {
          setIsTesting(null);
          toast({
            variant: "destructive",
            title: "Error",
            description:
              "Failed to start connection test. No task ID received.",
          });
        }
      } else if (result.error) {
        setIsTesting(null);
        toast({
          variant: "destructive",
          title: "Connection Test Failed",
          description: result.error,
        });
      }
    } catch (error) {
      setIsTesting(null);
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to test connection. Please try again.",
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
    // Reset loading state after a short delay to show the skeleton briefly
    setTimeout(() => {
      setIsOperationLoading(false);
    }, 1500);
  };

  return (
    <>
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
                  <div className="flex items-center justify-between">
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
                        onPress={() => handleEditConfiguration(integration)}
                        ariaLabel="Edit configuration"
                      >
                        Config
                      </CustomButton>
                      <CustomButton
                        size="sm"
                        variant="bordered"
                        startContent={<SettingsIcon size={14} />}
                        onPress={() => handleEditCredentials(integration)}
                        ariaLabel="Edit credentials"
                      >
                        Credentials
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
        ) : null}
      </div>
    </>
  );
};
