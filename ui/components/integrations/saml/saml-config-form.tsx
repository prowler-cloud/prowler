"use client";

import {
  Dispatch,
  SetStateAction,
  useActionState,
  useEffect,
  useRef,
  useState,
} from "react";
import { z } from "zod";

import { createSamlConfig, updateSamlConfig } from "@/actions/integrations";
import { AddIcon } from "@/components/icons";
import { Button, Card, CardContent, CardHeader } from "@/components/shadcn";
import { useToast } from "@/components/ui";
import { CustomServerInput } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { SnippetChip } from "@/components/ui/entities";
import { FormButtons } from "@/components/ui/form";
import { apiBaseUrl } from "@/lib";

const validateXMLContent = (
  xmlContent: string,
): { isValid: boolean; error?: string } => {
  try {
    // Basic checks
    if (!xmlContent || !xmlContent.trim()) {
      return {
        isValid: false,
        error: "XML content is empty.",
      };
    }

    const trimmedContent = xmlContent.trim();

    // Check if it starts and ends with XML tags
    if (!trimmedContent.startsWith("<") || !trimmedContent.endsWith(">")) {
      return {
        isValid: false,
        error: "Content does not appear to be valid XML format.",
      };
    }

    // Use DOMParser to validate XML structure
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(xmlContent, "text/xml");

    // Check for parser errors
    const parserError = xmlDoc.querySelector("parsererror");
    if (parserError) {
      const errorText = parserError.textContent || "Unknown XML parsing error";
      return {
        isValid: false,
        error: `XML parsing error: ${errorText.substring(0, 100)}...`,
      };
    }

    // Check if the document has a root element
    if (!xmlDoc.documentElement) {
      return {
        isValid: false,
        error: "XML does not have a valid root element.",
      };
    }

    // Optional: Check for basic SAML metadata structure
    const rootElement = xmlDoc.documentElement;
    const rootTagName = rootElement.tagName.toLowerCase();

    // Check if it looks like SAML metadata (common root elements)
    const samlRootElements = [
      "entitydescriptor",
      "entitiesDescriptor",
      "metadata",
      "md:entitydescriptor",
      "md:entitiesdescriptor",
    ];

    const isSamlMetadata = samlRootElements.some((element) =>
      rootTagName.includes(element.toLowerCase()),
    );

    if (!isSamlMetadata) {
      // Check for common SAML namespace attributes
      const xmlString = xmlContent.toLowerCase();
      const hasSamlNamespace =
        xmlString.includes("saml") ||
        xmlString.includes("urn:oasis:names:tc:saml") ||
        xmlString.includes("metadata");

      if (!hasSamlNamespace) {
        return {
          isValid: false,
          error:
            "The XML file does not appear to be SAML metadata. Please ensure you're uploading the correct SAML metadata file from your Identity Provider.",
        };
      }
    }

    return { isValid: true };
  } catch (error) {
    return {
      isValid: false,
      error:
        error instanceof Error
          ? error.message
          : "Failed to validate XML content.",
    };
  }
};

export const SamlConfigForm = ({
  setIsOpen,
  samlConfig,
}: {
  setIsOpen: Dispatch<SetStateAction<boolean>>;
  samlConfig?: any;
}) => {
  const [state, formAction, isPending] = useActionState(
    samlConfig?.id ? updateSamlConfig : createSamlConfig,
    null,
  );
  const [emailDomain, setEmailDomain] = useState(
    samlConfig?.attributes?.email_domain || "",
  );
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [clientErrors, setClientErrors] = useState<{
    email_domain?: string | null;
    metadata_xml?: string | null;
  }>({});
  const formRef = useRef<HTMLFormElement>(null);
  const { toast } = useToast();

  // Client-side validation function
  const validateFields = (email: string, hasFile: boolean) => {
    // Validar cada campo por separado para poder limpiarlos individualmente
    const emailValidation = z
      .string()
      .trim()
      .min(1, { message: "Email domain is required" })
      .safeParse(email);
    const metadataValidation = z
      .string()
      .trim()
      .min(1, { message: "Metadata XML is required" })
      .safeParse(hasFile ? "dummy_xml_content" : "");

    const newErrors = {
      email_domain: emailValidation.success
        ? null
        : emailValidation.error.issues[0]?.message,
      metadata_xml: metadataValidation.success
        ? null
        : metadataValidation.error.issues[0]?.message,
    };

    setClientErrors(newErrors);
  };

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
      setUploadedFile(null);
      validateFields(emailDomain, false);
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
      setUploadedFile(null);
      validateFields(emailDomain, false);

      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;

      // Comprehensive XML validation
      const xmlValidationResult = validateXMLContent(content);
      if (!xmlValidationResult.isValid) {
        toast({
          variant: "destructive",
          title: "Invalid XML content",
          description: xmlValidationResult.error,
        });
        // Clear the file input
        event.target.value = "";
        setUploadedFile(null);
        validateFields(emailDomain, false);
        return;
      }

      // Set the XML content in a hidden input
      const xmlInput = document.getElementById(
        "metadata_xml",
      ) as HTMLInputElement;
      if (xmlInput) {
        xmlInput.value = content;
      }

      setUploadedFile(file);
      validateFields(emailDomain, true);

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
      setUploadedFile(null);
      validateFields(emailDomain, false);
    };

    reader.readAsText(file);
  };

  const acsUrl = emailDomain
    ? `${apiBaseUrl}/accounts/saml/${emailDomain}/acs/`
    : `${apiBaseUrl}/accounts/saml/your-domain.com/acs/`;

  return (
    <form ref={formRef} action={formAction} className="flex flex-col gap-2">
      <div className="py-1 text-xs">
        Need help configuring SAML SSO?{" "}
        <CustomLink
          href={
            "https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-sso/"
          }
        >
          Read the docs
        </CustomLink>
      </div>
      <input type="hidden" name="id" value={samlConfig?.id || ""} />
      <CustomServerInput
        name="email_domain"
        label="Email Domain"
        placeholder="Enter your email domain (e.g., company.com)"
        labelPlacement="outside"
        variant="bordered"
        isRequired={true}
        isInvalid={
          !!(clientErrors.email_domain === null
            ? undefined
            : clientErrors.email_domain || state?.errors?.email_domain)
        }
        errorMessage={
          clientErrors.email_domain === null
            ? undefined
            : clientErrors.email_domain || state?.errors?.email_domain
        }
        value={emailDomain}
        onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
          const newValue = e.target.value;
          setEmailDomain(newValue);
        }}
      />

      <Card variant="inner">
        <CardHeader className="mb-2">
          Identity Provider Configuration
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-4">
            <div>
              <span className="mb-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
                ACS URL:
              </span>
              <SnippetChip
                value={acsUrl}
                ariaLabel="Copy ACS URL to clipboard"
                className="h-10 w-full"
              />
            </div>

            <div>
              <span className="mb-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
                Audience:
              </span>
              <SnippetChip
                value="urn:prowler.com:sp"
                ariaLabel="Copy Audience to clipboard"
                className="h-10 w-full"
              />
            </div>

            <div>
              <span className="mb-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
                Name ID Format:
              </span>
              <span className="w-full text-sm text-gray-600 dark:text-gray-400">
                urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
              </span>
            </div>

            <div>
              <span className="mb-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
                Supported Assertion Attributes:
              </span>
              <ul className="ml-4 flex flex-col gap-1 text-sm text-gray-600 dark:text-gray-400">
                <li>• firstName</li>
                <li>• lastName</li>
                <li>• userType</li>
                <li>• organization</li>
              </ul>
              <p className="mt-2 text-xs text-gray-600 dark:text-gray-400">
                <strong>Note:</strong> The userType attribute will be used to
                assign the user&apos;s role. If the role does not exist, one
                will be created with minimal permissions. You can assign
                permissions to roles on the{" "}
                <CustomLink href="/roles" target="_self">
                  <span>Roles</span>
                </CustomLink>{" "}
                page.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
      <div className="flex flex-col items-start gap-2">
        <span className="text-xs text-gray-700 dark:text-gray-300">
          Metadata XML File <span className="text-red-500">*</span>
        </span>
        <Button
          type="button"
          variant="outline"
          disabled={isPending}
          onClick={() => {
            const fileInput = document.getElementById(
              "metadata_xml_file",
            ) as HTMLInputElement;
            if (fileInput) {
              fileInput.click();
            }
          }}
          className={`justify-start gap-2 ${
            (
              clientErrors.metadata_xml === null
                ? undefined
                : clientErrors.metadata_xml || state?.errors?.metadata_xml
            )
              ? "border-red-500"
              : uploadedFile
                ? "border-green-500 bg-green-50 dark:bg-green-900/20"
                : ""
          }`}
        >
          <AddIcon size={20} />
          <span className="text-sm">
            {uploadedFile ? (
              <span className="flex items-center gap-2">
                <span className="max-w-36 truncate">{uploadedFile.name}</span>
              </span>
            ) : (
              "Choose File"
            )}
          </span>
        </Button>

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
          {(() => {
            const finalError =
              clientErrors.metadata_xml === null
                ? undefined
                : clientErrors.metadata_xml || state?.errors?.metadata_xml;
            return finalError;
          })()}
        </span>
      </div>
      <FormButtons
        setIsOpen={setIsOpen}
        submitText={samlConfig?.id ? "Update" : "Save"}
      />
    </form>
  );
};
