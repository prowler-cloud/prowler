"use client";

import { Modal, ModalBody, ModalContent, ModalFooter, ModalHeader } from "@nextui-org/react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { bulkImportProviders } from "@/actions/providers/providers";
import { useToast } from "@/components/ui";
import { CustomButton, CustomTextarea } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { bulkProviderImportFormSchema } from "@/types";

export type BulkImportFormValues = z.infer<typeof bulkProviderImportFormSchema>;

interface BulkImportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

export const BulkImportModal = ({ isOpen, onClose, onSuccess }: BulkImportModalProps) => {
  const { toast } = useToast();
  const [isSubmitting, setIsSubmitting] = useState(false);

  const form = useForm<BulkImportFormValues>({
    resolver: zodResolver(bulkProviderImportFormSchema),
    defaultValues: {
      yamlContent: "",
    },
  });

  const onSubmit = async (values: BulkImportFormValues) => {
    setIsSubmitting(true);

    const formData = new FormData();
    formData.append("yamlContent", values.yamlContent);

    try {
      const result = await bulkImportProviders(formData);

      if (result?.error) {
        toast({
          variant: "destructive",
          title: "Import Failed",
          description: result.error,
        });
      } else if (result?.success) {
        const { summary, errors } = result;
        
        if (errors && errors.length > 0) {
          toast({
            variant: "destructive",
            title: "Partial Import Success",
            description: `${summary.successful} of ${summary.total} providers imported successfully. ${errors.length} failed.`,
          });
        } else {
          toast({
            variant: "default",
            title: "Import Successful",
            description: `Successfully imported ${summary.successful} provider${summary.successful === 1 ? '' : 's'}.`,
          });
        }

        form.reset();
        onClose();
        onSuccess?.();
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Import Error",
        description: error instanceof Error ? error.message : "An unexpected error occurred",
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleClose = () => {
    if (!isSubmitting) {
      form.reset();
      onClose();
    }
  };

  const exampleYaml = `# Example YAML configuration for bulk provider import
- provider: aws
  uid: "123456789012"
  alias: "production-account"
  auth_method: role
  credentials:
    role_arn: "arn:aws:iam::123456789012:role/ProwlerScanRole"
    external_id: "prowler-external-id"

- provider: azure
  uid: "00000000-1111-2222-3333-444444444444"
  alias: "azure-production"
  auth_method: service_principal
  credentials:
    tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    client_id: "ffffffff-1111-2222-3333-444444444444"
    client_secret: "your-client-secret"

- provider: gcp
  uid: "my-gcp-project"
  alias: "gcp-production"
  auth_method: service_account
  credentials:
    inline_json:
      type: "service_account"
      project_id: "my-gcp-project"
      private_key_id: "key-id"
      private_key: "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n"
      client_email: "service-account@project.iam.gserviceaccount.com"
      client_id: "123456789"
      auth_uri: "https://accounts.google.com/o/oauth2/auth"
      token_uri: "https://oauth2.googleapis.com/token"`;

  return (
    <Modal 
      isOpen={isOpen} 
      onOpenChange={(open) => !open && handleClose()} 
      size="4xl"
      classNames={{
        base: "dark:bg-prowler-blue-800",
        closeButton: "rounded-md",
      }}
      backdrop="blur"
      placement="center"
      scrollBehavior="inside"
    >
      <ModalContent className="py-4">
        {(_onClose) => (
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)}>
              <ModalHeader className="flex flex-col gap-1 py-0">
                <h2 className="text-xl font-semibold">Bulk Import Providers</h2>
                <p className="text-sm text-gray-600 dark:text-gray-300">
                  Import multiple cloud providers at once using YAML configuration
                </p>
              </ModalHeader>
              <ModalBody>
                <div className="space-y-4">
                  <CustomTextarea
                    control={form.control}
                    name="yamlContent"
                    label="YAML Configuration"
                    placeholder={exampleYaml}
                    variant="bordered"
                    minRows={15}
                    maxRows={25}
                    isRequired
                    isInvalid={!!form.formState.errors.yamlContent}
                    description="Paste your YAML configuration here. Each provider entry should include provider type, UID, alias, and credentials."
                  />
                  
                  <div className="bg-gray-50 dark:bg-prowler-blue-700 p-4 rounded-lg">
                    <h3 className="font-medium text-sm mb-2">Supported Provider Types:</h3>
                    <div className="grid grid-cols-2 gap-2 text-sm text-gray-600 dark:text-gray-300">
                      <div>• aws (Account ID)</div>
                      <div>• azure (Subscription ID)</div>
                      <div>• gcp (Project ID)</div>
                      <div>• kubernetes (Context)</div>
                      <div>• m365 (Domain ID)</div>
                      <div>• github (Username)</div>
                    </div>
                  </div>
                </div>
              </ModalBody>
              <ModalFooter>
                <CustomButton
                  type="button"
                  variant="faded"
                  onPress={handleClose}
                  isDisabled={isSubmitting}
                >
                  Cancel
                </CustomButton>
                <CustomButton
                  type="submit"
                  variant="solid"
                  color="action"
                  isLoading={isSubmitting}
                >
                  {isSubmitting ? "Importing..." : "Import Providers"}
                </CustomButton>
              </ModalFooter>
            </form>
          </Form>
        )}
      </ModalContent>
    </Modal>
  );
};
