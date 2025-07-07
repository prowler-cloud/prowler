"use client";

import { Dispatch, SetStateAction, useEffect, useRef, useState } from "react";
import { useFormState } from "react-dom";

import { createSamlConfig, updateSamlConfig } from "@/actions/integrations";
import { AddIcon } from "@/components/icons";
import { useToast } from "@/components/ui";
import { CustomButton, CustomServerInput } from "@/components/ui/custom";
import { SnippetChip } from "@/components/ui/entities";
import { FormButtons } from "@/components/ui/form";

export const SamlConfigForm = ({
  setIsOpen,
  id,
}: {
  setIsOpen: Dispatch<SetStateAction<boolean>>;
  id: string;
}) => {
  const [state, formAction, isPending] = useFormState(
    id ? updateSamlConfig : createSamlConfig,
    null,
  );
  const [emailDomain, setEmailDomain] = useState("");
  const [uploadedFile, setUploadedFile] = useState<{
    name: string;
    uploaded: boolean;
  }>({ name: "", uploaded: false });
  const formRef = useRef<HTMLFormElement>(null);
  const { toast } = useToast();

  useEffect(() => {
    if (state?.success) {
      toast({
        title: "Configuration saved successfully",
        description: state.success,
      });
      setIsOpen(false);
    } else if (state?.errors?.general) {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: state.errors.general,
      });
    }
  }, [state, toast, setIsOpen]);

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      setUploadedFile({ name: "", uploaded: false });
      return;
    }

    // Check file extension
    const isXmlFile =
      file.name.toLowerCase().endsWith(".xml") ||
      file.type === "text/xml" ||
      file.type === "application/xml";

    if (!isXmlFile) {
      toast({
        variant: "destructive",
        title: "Invalid file type",
        description: "Please select a valid XML file (.xml extension).",
      });
      // Clear the file input
      event.target.value = "";
      setUploadedFile({ name: "", uploaded: false });

      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;

      // Basic XML validation
      if (!content.trim().startsWith("<") || !content.includes("</")) {
        toast({
          variant: "destructive",
          title: "Invalid XML content",
          description: "The file does not contain valid XML content.",
        });
        // Clear the file input
        event.target.value = "";
        setUploadedFile({ name: "", uploaded: false });
        return;
      }

      // Set the XML content in a hidden input
      const xmlInput = document.getElementById(
        "metadata_xml",
      ) as HTMLInputElement;
      if (xmlInput) {
        xmlInput.value = content;
      }

      // Update file state
      setUploadedFile({ name: file.name, uploaded: true });

      toast({
        title: "File uploaded successfully",
        description: "XML metadata file has been loaded.",
      });
    };

    reader.onerror = () => {
      toast({
        variant: "destructive",
        title: "File read error",
        description: "Failed to read the selected file.",
      });
      // Clear the file input
      event.target.value = "";
      setUploadedFile({ name: "", uploaded: false });
    };

    reader.readAsText(file);
  };

  const acsUrl = emailDomain
    ? `https://app.prowler.pro/saml/sp/consume/${emailDomain}`
    : "https://app.prowler.pro/saml/sp/consume/your-domain.com";

  return (
    <form ref={formRef} action={formAction} className="flex flex-col space-y-6">
      <input type="hidden" name="id" value={id} />
      <div className="space-y-4">
        <CustomServerInput
          name="email_domain"
          label="Email Domain"
          placeholder="Enter your email domain (e.g., company.com)"
          labelPlacement="outside"
          variant="bordered"
          isRequired={true}
          isInvalid={!!state?.errors?.email_domain}
          errorMessage={state?.errors?.email_domain}
          value={emailDomain}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
            setEmailDomain(e.target.value);
          }}
        />

        <div className="flex flex-col items-start space-y-2">
          <span className="text-xs text-default-500">
            Metadata XML File <span className="text-red-500">*</span>
          </span>
          <CustomButton
            type="button"
            ariaLabel="Select Metadata XML File"
            isDisabled={isPending}
            onPress={() => {
              const fileInput = document.getElementById(
                "metadata_xml_file",
              ) as HTMLInputElement;
              if (fileInput) {
                fileInput.click();
              }
            }}
            startContent={<AddIcon size={20} />}
            className={`h-10 justify-start rounded-medium border-2 text-default-500 ${
              state?.errors?.metadata_xml
                ? "border-red-500"
                : uploadedFile.uploaded
                  ? "border-green-500 bg-green-50 dark:bg-green-900/20"
                  : "border-default-200"
            }`}
          >
            <span className="text-small">
              {uploadedFile.uploaded ? (
                <span className="flex items-center space-x-2">
                  <span className="max-w-36 truncate">{uploadedFile.name}</span>
                </span>
              ) : (
                "Choose File"
              )}
            </span>
          </CustomButton>

          <input
            type="file"
            id="metadata_xml_file"
            name="metadata_xml_file"
            accept=".xml,application/xml,text/xml"
            className="hidden"
            disabled={isPending}
            onChange={handleFileUpload}
          />
          <input type="hidden" id="metadata_xml" name="metadata_xml" />
          <p className="text-xs text-gray-500">
            Upload your Identity Provider&apos;s SAML metadata XML file
          </p>
          <span className="text-xs text-red-500">
            {state?.errors?.metadata_xml}
          </span>
        </div>
      </div>

      <div className="space-y-4 rounded-lg bg-gray-50 p-4 dark:bg-gray-800">
        <h3 className="text-lg font-semibold">
          Identity Provider Configuration
        </h3>

        <div className="space-y-4">
          <div>
            <span className="mb-2 block text-sm font-medium text-default-500">
              ACS URL:
            </span>
            <SnippetChip
              value={acsUrl}
              ariaLabel="Copy ACS URL to clipboard"
              className="w-full"
            />
          </div>

          <div>
            <span className="mb-2 block text-sm font-medium text-default-500">
              Audience:
            </span>
            <SnippetChip
              value="urn:prowler.com:sp"
              ariaLabel="Copy Audience to clipboard"
              className="w-full"
            />
          </div>

          <div>
            <span className="mb-2 block text-sm font-medium text-default-500">
              Name ID Format:
            </span>
            <SnippetChip
              value="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
              ariaLabel="Copy Name ID Format to clipboard"
              className="w-full"
            />
          </div>

          <div>
            <span className="mb-2 block text-sm font-medium text-default-500">
              Supported Assertion Attributes:
            </span>
            <ul className="ml-4 space-y-1 text-sm text-default-600">
              <li>• firstName</li>
              <li>• lastName</li>
              <li>• userType</li>
              <li>• organization</li>
            </ul>
            <p className="mt-2 text-xs text-gray-600 dark:text-gray-400">
              <strong>Note:</strong> The userType attribute will be used to
              assign the user&apos;s role. If the role does not exist, one will
              be created with minimal permissions. You can assign permissions to
              roles on the Roles page.
            </p>
          </div>
        </div>
      </div>

      <FormButtons setIsOpen={setIsOpen} submitText={id ? "Update" : "Save"} />
    </form>
  );
};
