"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";

import { createIntegration, updateIntegration } from "@/actions/integrations";
import { useToast } from "@/components/ui";
import { CustomInput } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { Form } from "@/components/ui/form";
import { FormButtons } from "@/components/ui/form/form-buttons";
import {
  editGitHubIntegrationFormSchema,
  type GitHubCreateValues,
  type GitHubCredentialsPayload,
  type GitHubFormValues,
  githubIntegrationFormSchema,
  IntegrationProps,
} from "@/types/integrations";

interface GitHubIntegrationFormProps {
  integration?: IntegrationProps | null;
  onSuccess: (integrationId?: string, shouldTestConnection?: boolean) => void;
  onCancel: () => void;
}

export const GitHubIntegrationForm = ({
  integration,
  onSuccess,
  onCancel,
}: GitHubIntegrationFormProps) => {
  const { toast } = useToast();
  const isEditing = !!integration;
  const isCreating = !isEditing;

  const form = useForm<GitHubFormValues>({
    resolver: zodResolver(
      isCreating
        ? githubIntegrationFormSchema
        : editGitHubIntegrationFormSchema,
    ),
    defaultValues: {
      integration_type: "github" as const,
      owner: integration?.attributes.configuration.owner || "",
      enabled: integration?.attributes.enabled ?? true,
      token: "",
    },
  });

  const isLoading = form.formState.isSubmitting;

  const onSubmit = async (data: GitHubFormValues) => {
    try {
      const formData = new FormData();

      // Add integration type
      formData.append("integration_type", "github");

      // Prepare credentials object
      const credentials: GitHubCredentialsPayload = {};

      // For editing, only add fields that have values
      if (isEditing) {
        if (data.token) credentials.token = data.token;
        if (data.owner) credentials.owner = data.owner.trim();
      } else {
        // For creation, token is required
        const createData = data as GitHubCreateValues;
        credentials.token = createData.token;
        if (createData.owner) credentials.owner = createData.owner.trim();
      }

      // Add credentials as JSON
      if (Object.keys(credentials).length > 0) {
        formData.append("credentials", JSON.stringify(credentials));
      }

      // For creation, we need to provide configuration and providers
      if (isCreating) {
        formData.append("configuration", JSON.stringify({}));
        formData.append("providers", JSON.stringify([]));
        // enabled exists only in create schema
        formData.append(
          "enabled",
          JSON.stringify((data as GitHubCreateValues).enabled),
        );
      }

      type IntegrationResult =
        | { success: string; integrationId?: string }
        | { error: string };
      let result: IntegrationResult;
      if (isEditing) {
        result = await updateIntegration(integration.id, formData);
      } else {
        result = await createIntegration(formData);
      }

      if (result && "success" in result && result.success) {
        toast({
          title: "Success!",
          description: `GitHub integration ${isEditing ? "updated" : "created"} successfully.`,
        });

        // Always test connection when creating or updating
        const shouldTestConnection = true;
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
        description: `Failed to ${isEditing ? "update" : "create"} GitHub integration. Please try again.`,
      });
    }
  };

  const renderForm = () => {
    return (
      <>
        <CustomInput
          control={form.control}
          name="token"
          type="password"
          label="Personal Access Token"
          labelPlacement="inside"
          placeholder="ghp_xxxxxxxxxxxx"
          isRequired
          isDisabled={isLoading}
        />

        <CustomInput
          control={form.control}
          name="owner"
          type="text"
          label="Repository Owner (Optional)"
          labelPlacement="inside"
          placeholder="myorg or myusername"
          isDisabled={isLoading}
        />

        <div className="rounded-lg border border-blue-200 bg-blue-50 p-4 dark:border-blue-800 dark:bg-blue-900/20">
          <p className="text-sm text-blue-800 dark:text-blue-200">
            To generate a Personal Access Token with the <code>repo</code>{" "}
            scope, visit your{" "}
            <a
              href="https://github.com/settings/tokens/new"
              target="_blank"
              rel="noopener noreferrer"
              className="font-medium underline"
            >
              GitHub token settings
            </a>
            . The owner field is optional and filters repositories by user or
            organization.
          </p>
        </div>
      </>
    );
  };

  const getButtonLabel = () => {
    if (isEditing) {
      return "Update Credentials";
    }
    return "Create Integration";
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmit)}
        className="flex flex-col gap-6"
      >
        <div className="flex flex-col gap-4">
          <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center">
            <p className="text-default-500 flex items-center gap-2 text-sm">
              Need help configuring your GitHub integration?
            </p>
            <CustomLink
              href="https://docs.prowler.com"
              target="_blank"
              size="sm"
            >
              Read the docs
            </CustomLink>
          </div>
          {renderForm()}
        </div>
        <FormButtons
          setIsOpen={() => {}}
          onCancel={onCancel}
          submitText={getButtonLabel()}
          cancelText="Cancel"
          loadingText="Processing..."
          isDisabled={isLoading}
        />
      </form>
    </Form>
  );
};
