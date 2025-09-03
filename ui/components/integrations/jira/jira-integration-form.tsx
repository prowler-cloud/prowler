"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Divider } from "@nextui-org/react";
import { ArrowLeftIcon, ArrowRightIcon } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";

import { createIntegration, updateIntegration } from "@/actions/integrations";
import { EnhancedProviderSelector } from "@/components/providers/enhanced-provider-selector";
import { useToast } from "@/components/ui";
import { CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { FormButtons } from "@/components/ui/form/form-buttons";
import {
  editJiraIntegrationFormSchema,
  IntegrationProps,
  jiraIntegrationFormSchema,
} from "@/types/integrations";
import { ProviderProps } from "@/types/providers";

interface JiraIntegrationFormProps {
  integration?: IntegrationProps | null;
  providers: ProviderProps[];
  onSuccess: (integrationId?: string, shouldTestConnection?: boolean) => void;
  onCancel: () => void;
  editMode?: "configuration" | "credentials" | null; // null means creating new
}

export const JiraIntegrationForm = ({
  integration,
  providers,
  onSuccess,
  onCancel,
  editMode = null,
}: JiraIntegrationFormProps) => {
  const { toast } = useToast();
  const [currentStep, setCurrentStep] = useState(
    editMode === "credentials" ? 1 : 0,
  );
  const isEditing = !!integration;
  const isCreating = !isEditing;
  const isEditingConfig = editMode === "configuration";
  const isEditingCredentials = editMode === "credentials";

  const form = useForm({
    resolver: zodResolver(
      // For credentials editing, use creation schema (all fields required)
      // For config editing, use edit schema (partial updates allowed)
      // For creation, use creation schema
      isEditingCredentials || isCreating
        ? jiraIntegrationFormSchema
        : editJiraIntegrationFormSchema,
    ),
    defaultValues: {
      integration_type: "jira" as const,
      domain: integration?.attributes.configuration.domain || "",
      project_key: integration?.attributes.configuration.project_key || "",
      providers:
        integration?.relationships?.providers?.data?.map((p) => p.id) || [],
      enabled: integration?.attributes.enabled ?? true,
      user_mail: "",
      api_token: "",
    },
  });

  const isLoading = form.formState.isSubmitting;

  const handlePrevious = () => {
    setCurrentStep(0);
  };

  const onSubmit = async (data: any) => {
    try {
      const formData = new FormData();

      // Add integration type
      formData.append("integration_type", "jira");

      // Prepare configuration object
      const configuration: any = {};
      if (data.domain) configuration.domain = data.domain;
      if (data.project_key) configuration.project_key = data.project_key;

      // Prepare credentials object
      const credentials: any = {};
      if (data.user_mail) credentials.user_mail = data.user_mail;
      if (data.api_token) credentials.api_token = data.api_token;

      // Add configuration and credentials as JSON
      if (Object.keys(configuration).length > 0) {
        formData.append("configuration", JSON.stringify(configuration));
      }
      if (Object.keys(credentials).length > 0) {
        formData.append("credentials", JSON.stringify(credentials));
      }

      // Add enabled status
      formData.append("enabled", JSON.stringify(data.enabled));

      // Add providers
      if (data.providers) {
        formData.append("providers", JSON.stringify(data.providers));
      }

      let result;
      if (isEditing) {
        result = await updateIntegration(integration.id, formData);
      } else {
        result = await createIntegration(formData);
      }

      if (result && "success" in result && result.success) {
        toast({
          title: "Success!",
          description: `Jira integration ${isEditing ? "updated" : "created"} successfully.`,
        });

        // Trigger test connection if we're creating or editing credentials
        const shouldTestConnection = isCreating || isEditingCredentials;
        const integrationId =
          "integrationId" in result ? result.integrationId : integration?.id;

        onSuccess(integrationId, shouldTestConnection);
      } else if (result && "error" in result) {
        toast({
          variant: "destructive",
          title: "Operation Failed",
          description: result.error,
        });
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: `Failed to ${isEditing ? "update" : "create"} Jira integration. Please try again.`,
      });
    }
  };

  const renderStep = () => {
    if (currentStep === 0 && !isEditingCredentials) {
      return (
        <>
          <EnhancedProviderSelector
            control={form.control}
            name="providers"
            label="Select Cloud Providers"
            providers={providers}
            isInvalid={!!form.formState.errors.providers}
            selectionMode="multiple"
            enableSearch={true}
          />

          <Divider />

          <CustomInput
            control={form.control}
            name="domain"
            type="text"
            label="Jira Domain"
            labelPlacement="inside"
            placeholder="your-domain.atlassian.net"
            isRequired
            isDisabled={isLoading}
            isInvalid={!!form.formState.errors.domain}
          />

          <CustomInput
            control={form.control}
            name="project_key"
            type="text"
            label="Project Key"
            labelPlacement="inside"
            placeholder="e.g., PROJ"
            isRequired
            isDisabled={isLoading}
            isInvalid={!!form.formState.errors.project_key}
          />
        </>
      );
    }

    // Step 2: Credentials (or credentials edit mode)
    return (
      <>
        <CustomInput
          control={form.control}
          name="user_mail"
          type="email"
          label="User Email"
          labelPlacement="inside"
          placeholder="user@example.com"
          isRequired
          isDisabled={isLoading}
          isInvalid={!!form.formState.errors.user_mail}
        />

        <CustomInput
          control={form.control}
          name="api_token"
          type="password"
          label="API Token"
          labelPlacement="inside"
          placeholder="Enter your Jira API token"
          isRequired
          isDisabled={isLoading}
          isInvalid={!!form.formState.errors.api_token}
        />

        <div className="rounded-lg border border-blue-200 bg-blue-50 p-4 dark:border-blue-800 dark:bg-blue-900/20">
          <p className="text-sm text-blue-800 dark:text-blue-200">
            To generate an API token, visit your{" "}
            <a
              href="https://id.atlassian.com/manage-profile/security/api-tokens"
              target="_blank"
              rel="noopener noreferrer"
              className="font-medium underline"
            >
              Atlassian account settings
            </a>
            .
          </p>
        </div>
      </>
    );
  };

  const getButtonLabel = () => {
    if (currentStep === 0 && !isEditingConfig && !isEditingCredentials) {
      return "Next";
    }
    if (isEditingConfig) {
      return "Update Configuration";
    }
    if (isEditingCredentials) {
      return "Update Credentials";
    }
    if (isEditing) {
      return "Update Integration";
    }
    return "Create Integration";
  };

  const showPreviousButton =
    currentStep === 1 && !isEditingConfig && !isEditingCredentials;

  return (
    <Form {...form}>
      <form
        onSubmit={
          currentStep === 0 && !isEditingConfig && !isEditingCredentials
            ? async (e) => {
                e.preventDefault();
                const stepFields = [
                  "domain",
                  "project_key",
                  "providers",
                ] as const;
                const isValid = await form.trigger(stepFields);
                if (isValid) {
                  setCurrentStep(1);
                }
              }
            : form.handleSubmit(onSubmit)
        }
        className="space-y-6"
      >
        {renderStep()}

        <FormButtons
          setIsOpen={() => {}}
          onCancel={showPreviousButton ? handlePrevious : onCancel}
          submitText={getButtonLabel()}
          cancelText={showPreviousButton ? "Back" : "Cancel"}
          loadingText="Processing..."
          isDisabled={isLoading}
          leftIcon={
            showPreviousButton ? <ArrowLeftIcon size={24} /> : undefined
          }
          rightIcon={
            currentStep === 0 && !isEditingConfig && !isEditingCredentials ? (
              <ArrowRightIcon size={24} />
            ) : undefined
          }
        />
      </form>
    </Form>
  );
};
