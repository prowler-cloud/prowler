"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { PlusIcon, XIcon } from "lucide-react";
import { type Dispatch, type SetStateAction, useRef, useState } from "react";
import { useForm } from "react-hook-form";

import { createSamlConfig, updateSamlConfig } from "@/actions/integrations";
import { AddIcon } from "@/components/icons";
import {
  Button,
  Badge,
  Card,
  CardContent,
  CardHeader,
  Field,
  FieldError,
  FieldLabel,
  Input,
  useToast,
} from "@/components/shadcn";
import { CodeSnippet } from "@/components/shadcn/code-snippet/code-snippet";
import { CustomInput } from "@/components/shadcn/custom";
import { CustomLink } from "@/components/shadcn/custom/custom-link";
import { Form, FormButtons } from "@/components/shadcn/form";
import { useRuntimeConfig } from "@/hooks/use-runtime-config";
import { isCloud } from "@/lib/shared/env";
import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";
import {
  getSamlConfigFormSchema,
  samlAdditionalEmailDomainSchema,
  samlEmailDomainSchema,
  type SamlConfigFormInput,
  type SamlConfigFormValues,
} from "@/types/formSchemas";
import {
  MAX_SAML_ADDITIONAL_EMAIL_DOMAINS,
  type SamlConfiguration,
  type SamlConfigurationErrors,
} from "@/types/saml";

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
  samlConfig?: SamlConfiguration;
}) => {
  const isUpdate = Boolean(samlConfig?.id);
  const formSchema = getSamlConfigFormSchema(isUpdate);
  const form = useForm<SamlConfigFormInput, unknown, SamlConfigFormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      email_domain: samlConfig?.attributes?.email_domain ?? "",
      additional_email_domains:
        samlConfig?.attributes?.additional_email_domains ?? [],
      metadata_xml: "",
    },
  });
  const emailDomain = form.watch("email_domain");
  const additionalEmailDomains = form.watch("additional_email_domains") ?? [];
  const isPending = form.formState.isSubmitting;
  const [additionalDomainDraft, setAdditionalDomainDraft] = useState("");
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  // Local state needed: submission must wait for the selected metadata file.
  const [isMetadataFileReading, setIsMetadataFileReading] = useState(false);
  const activeFileReaderRef = useRef<FileReader | null>(null);
  const { toast } = useToast();
  const isCloudEnv = isCloud();
  const openCloudUpgrade = useCloudUpgradeStore(
    (storeState) => storeState.openCloudUpgrade,
  );
  const additionalDomainsError =
    form.formState.errors.additional_email_domains?.message;

  const setAdditionalDomainsError = (message: string) => {
    form.setError("additional_email_domains", {
      type: "manual",
      message,
    });
  };

  const addAdditionalDomain = () => {
    const validation = samlAdditionalEmailDomainSchema.safeParse(
      additionalDomainDraft,
    );
    if (!validation.success) {
      setAdditionalDomainsError(
        validation.error.issues[0]?.message ??
          "Additional email domain is invalid",
      );
      return;
    }

    const normalizedDomain = validation.data;
    if (normalizedDomain === emailDomain.trim().toLowerCase()) {
      setAdditionalDomainsError(
        "An additional domain must differ from the primary email domain.",
      );
      return;
    }

    if (additionalEmailDomains.includes(normalizedDomain)) {
      setAdditionalDomainsError("This domain has already been added.");
      return;
    }

    if (additionalEmailDomains.length >= MAX_SAML_ADDITIONAL_EMAIL_DOMAINS) {
      setAdditionalDomainsError(
        `A SAML configuration supports up to ${MAX_SAML_ADDITIONAL_EMAIL_DOMAINS} additional email domains.`,
      );
      return;
    }

    form.setValue(
      "additional_email_domains",
      [...additionalEmailDomains, normalizedDomain],
      { shouldDirty: true },
    );
    setAdditionalDomainDraft("");
    form.clearErrors("additional_email_domains");
  };

  const removeAdditionalDomain = (domainToRemove: string) => {
    form.setValue(
      "additional_email_domains",
      additionalEmailDomains.filter((domain) => domain !== domainToRemove),
      { shouldDirty: true },
    );
    form.clearErrors("additional_email_domains");
  };

  const invalidateActiveFileRead = () => {
    const activeReader = activeFileReaderRef.current;
    activeFileReaderRef.current = null;
    activeReader?.abort();
  };

  const clearMetadataFile = (fileInput: HTMLInputElement) => {
    invalidateActiveFileRead();
    fileInput.value = "";
    form.setValue("metadata_xml", "", {
      shouldDirty: true,
      shouldValidate: form.formState.isSubmitted,
    });
    setIsMetadataFileReading(false);
    setUploadedFile(null);
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      clearMetadataFile(event.target);
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
      clearMetadataFile(event.target);

      return;
    }

    invalidateActiveFileRead();
    const reader = new FileReader();
    activeFileReaderRef.current = reader;
    setIsMetadataFileReading(true);
    reader.onload = (e) => {
      if (activeFileReaderRef.current !== reader) {
        return;
      }
      activeFileReaderRef.current = null;
      setIsMetadataFileReading(false);
      const content =
        typeof e.target?.result === "string" ? e.target.result : "";

      // Comprehensive XML validation
      const xmlValidationResult = validateXMLContent(content);
      if (!xmlValidationResult.isValid) {
        toast({
          variant: "destructive",
          title: "Invalid XML content",
          description: xmlValidationResult.error,
        });
        clearMetadataFile(event.target);
        return;
      }

      form.setValue("metadata_xml", content, {
        shouldDirty: true,
        shouldValidate: true,
      });
      setUploadedFile(file);

      toast({
        title: "File uploaded successfully",
        description: "XML metadata file has been loaded.",
      });
    };

    reader.onerror = () => {
      if (activeFileReaderRef.current !== reader) {
        return;
      }
      activeFileReaderRef.current = null;
      toast({
        variant: "destructive",
        title: "File read error",
        description: "Failed to read the selected file.",
      });
      clearMetadataFile(event.target);
    };

    reader.readAsText(file);
  };

  const setFieldErrors = (errors: SamlConfigurationErrors) => {
    if (errors.email_domain) {
      form.setError("email_domain", {
        type: "server",
        message: errors.email_domain,
      });
    }
    if (errors.additional_email_domains) {
      form.setError("additional_email_domains", {
        type: "server",
        message: errors.additional_email_domains,
      });
    }
    if (errors.metadata_xml) {
      form.setError("metadata_xml", {
        type: "server",
        message: errors.metadata_xml,
      });
    }
  };

  const onSubmit = async (values: SamlConfigFormValues) => {
    const pendingDomains = additionalDomainDraft.trim()
      ? [...values.additional_email_domains, additionalDomainDraft]
      : values.additional_email_domains;
    const validatedSubmission = formSchema.safeParse({
      ...values,
      additional_email_domains: pendingDomains,
    });

    if (!validatedSubmission.success) {
      const fieldErrors = validatedSubmission.error.flatten().fieldErrors;
      setFieldErrors({
        email_domain: fieldErrors.email_domain?.[0],
        additional_email_domains: fieldErrors.additional_email_domains?.[0],
        metadata_xml: fieldErrors.metadata_xml?.[0],
      });
      return;
    }

    const formData = new FormData();
    if (samlConfig?.id) {
      formData.set("id", samlConfig.id);
    }
    formData.set("email_domain", validatedSubmission.data.email_domain);
    validatedSubmission.data.additional_email_domains.forEach((domain) =>
      formData.append("additional_email_domains", domain),
    );
    formData.set("metadata_xml", validatedSubmission.data.metadata_xml);

    try {
      const result = isUpdate
        ? await updateSamlConfig(null, formData)
        : await createSamlConfig(null, formData);

      if (result?.success) {
        toast({
          title: "Configuration saved successfully",
          description: result.success,
        });
        setIsOpen(false);
        return;
      }

      if (result?.errors) {
        setFieldErrors(result.errors);
        if (result.errors.general) {
          toast({
            variant: "destructive",
            title: "Oops! Something went wrong",
            description: result.errors.general,
          });
        }
      }
    } catch {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: "Unable to save the SAML configuration. Please try again.",
      });
    }
  };

  const { apiBaseUrl } = useRuntimeConfig();
  const normalizedEmailDomain = samlEmailDomainSchema.safeParse(emailDomain);
  const acsEmailDomain = normalizedEmailDomain.success
    ? normalizedEmailDomain.data
    : "";
  const acsUrl =
    acsEmailDomain && apiBaseUrl
      ? `${apiBaseUrl}/accounts/saml/${acsEmailDomain}/acs/`
      : "";

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmit)}
        className="flex min-w-0 flex-col gap-2"
      >
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
        <CustomInput
          control={form.control}
          name="email_domain"
          label="Primary Email Domain"
          placeholder="Enter your primary email domain (e.g., company.com)"
          labelPlacement="outside"
          variant="bordered"
          isRequired
          isDisabled={isPending}
        />

        <Field>
          <div className="flex items-center justify-between gap-2">
            <FieldLabel
              htmlFor={isCloudEnv ? "additional_email_domain" : undefined}
            >
              Additional Email Domains
            </FieldLabel>
            {isCloudEnv ? (
              <span
                aria-live="polite"
                className="text-text-neutral-tertiary text-xs"
              >
                {additionalEmailDomains.length} /{" "}
                {MAX_SAML_ADDITIONAL_EMAIL_DOMAINS} domains
              </span>
            ) : (
              <Button
                type="button"
                variant="bare"
                size="link-sm"
                aria-label="Additional email domains are available in Prowler Cloud"
                onClick={() =>
                  openCloudUpgrade(CLOUD_UPGRADE_FEATURE.SAML_DOMAINS)
                }
              >
                <Badge variant="cloud">Available in Prowler Cloud</Badge>
              </Button>
            )}
          </div>
          <p className="text-text-neutral-tertiary text-xs">
            Allow users from other verified domains to use this same SAML
            configuration. The ACS URL always uses the primary domain.
          </p>
          {isCloudEnv && (
            <>
              <div className="flex items-center gap-2">
                <Input
                  id="additional_email_domain"
                  name={
                    additionalDomainDraft.trim()
                      ? "additional_email_domains"
                      : undefined
                  }
                  aria-label="Additional Email Domain"
                  placeholder="Enter an additional domain"
                  value={additionalDomainDraft}
                  disabled={
                    isPending ||
                    additionalEmailDomains.length >=
                      MAX_SAML_ADDITIONAL_EMAIL_DOMAINS
                  }
                  aria-invalid={Boolean(additionalDomainsError) || undefined}
                  onChange={(event) => {
                    setAdditionalDomainDraft(event.target.value);
                    form.clearErrors("additional_email_domains");
                  }}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") {
                      event.preventDefault();
                      addAdditionalDomain();
                    }
                  }}
                />
                <Button
                  type="button"
                  variant="outline"
                  disabled={
                    isPending ||
                    additionalEmailDomains.length >=
                      MAX_SAML_ADDITIONAL_EMAIL_DOMAINS
                  }
                  onClick={addAdditionalDomain}
                  aria-label="Add domain"
                >
                  <PlusIcon aria-hidden="true" />
                  Add
                </Button>
              </div>
              {additionalDomainsError && (
                <FieldError>{additionalDomainsError}</FieldError>
              )}
              {additionalEmailDomains.length > 0 && (
                <ul
                  aria-label="Additional email domains"
                  className="minimal-scrollbar border-border-neutral-secondary bg-bg-neutral-secondary flex max-h-24 flex-wrap content-start gap-2 overflow-y-auto rounded-lg border p-2"
                >
                  {additionalEmailDomains.map((domain) => (
                    <li key={domain}>
                      <Badge variant="tag">
                        {domain}
                        <Button
                          type="button"
                          variant="bare"
                          size="icon-xs"
                          disabled={isPending}
                          aria-label={`Remove ${domain}`}
                          onClick={() => removeAdditionalDomain(domain)}
                        >
                          <XIcon aria-hidden="true" />
                        </Button>
                      </Badge>
                    </li>
                  ))}
                </ul>
              )}
              {additionalEmailDomains.map((domain) => (
                <input
                  key={domain}
                  type="hidden"
                  name="additional_email_domains"
                  value={domain}
                />
              ))}
            </>
          )}
        </Field>

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
                <CodeSnippet
                  value={
                    acsUrl ||
                    "Enter your email domain above to generate the ACS URL."
                  }
                  ariaLabel="Copy ACS URL"
                  hideCopyButton={!acsUrl}
                  className="h-10 w-full"
                />
              </div>

              <div>
                <span className="mb-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Audience:
                </span>
                <CodeSnippet
                  value="urn:prowler.com:sp"
                  ariaLabel="Copy Audience"
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
            Metadata XML File{" "}
            {!isUpdate && <span className="text-red-500">*</span>}
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
              form.formState.errors.metadata_xml
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
          <input
            type="hidden"
            id="metadata_xml"
            {...form.register("metadata_xml")}
          />
          <p className="text-xs text-gray-500">
            Upload your Identity Provider&apos;s SAML metadata XML file
          </p>
          <span className="text-xs text-red-500">
            {form.formState.errors.metadata_xml?.message}
          </span>
        </div>
        <FormButtons
          setIsOpen={setIsOpen}
          submitText={samlConfig?.id ? "Update" : "Save"}
          isDisabled={isPending || isMetadataFileReading}
        />
      </form>
    </Form>
  );
};
