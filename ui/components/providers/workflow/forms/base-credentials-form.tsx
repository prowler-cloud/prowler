"use client";

import { Divider } from "@heroui/divider";
import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";
import { Control } from "react-hook-form";

import { CustomButton } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { useCredentialsForm } from "@/hooks/use-credentials-form";
import { getAWSCredentialsTemplateLinks } from "@/lib";
import { getCredentialFormComponent } from "@/lib/provider-credential-forms";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { requiresBackButton } from "@/lib/provider-helpers";
import { AWSCredentialsRole, ProviderType } from "@/types";

import { ProviderTitleDocs } from "../provider-title-docs";

type BaseCredentialsFormProps = {
  providerType: ProviderType;
  providerId: string;
  onSubmit: (formData: FormData) => Promise<any>;
  successNavigationUrl: string;
  submitButtonText?: string;
  showBackButton?: boolean;
};

export const BaseCredentialsForm = ({
  providerType,
  providerId,
  onSubmit,
  successNavigationUrl,
  submitButtonText = "Next",
  showBackButton = true,
}: BaseCredentialsFormProps) => {
  const {
    form,
    isLoading,
    handleSubmit,
    handleBackStep,
    searchParamsObj,
    externalId,
  } = useCredentialsForm({
    providerType,
    providerId,
    onSubmit,
    successNavigationUrl,
  });

  const templateLinks = getAWSCredentialsTemplateLinks(externalId);
  const credentialFormInfo = getCredentialFormComponent(
    providerType,
    searchParamsObj.get("via"),
  );

  if (!credentialFormInfo) return null;

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(handleSubmit)}
        className="flex flex-col gap-4"
      >
        <input
          type="hidden"
          name={ProviderCredentialFields.PROVIDER_ID}
          value={providerId}
        />
        <input
          type="hidden"
          name={ProviderCredentialFields.PROVIDER_TYPE}
          value={providerType}
        />

        <ProviderTitleDocs providerType={providerType} />

        <Divider />

        {credentialFormInfo.requiresExtendedProps &&
          credentialFormInfo.passesCredentialsType === false &&
          providerType === "aws" && (
            <credentialFormInfo.component
              control={form.control as unknown as Control<AWSCredentialsRole>}
              setValue={form.setValue as any}
              externalId={externalId}
              templateLinks={templateLinks}
            />
          )}
        {!credentialFormInfo.requiresExtendedProps &&
          credentialFormInfo.passesCredentialsType === true && (
            <credentialFormInfo.component
              control={form.control as unknown as Control}
              credentialsType={searchParamsObj.get("via") || undefined}
            />
          )}
        {!credentialFormInfo.requiresExtendedProps &&
          credentialFormInfo.passesCredentialsType === false && (
            <credentialFormInfo.component control={form.control as any} />
          )}

        <div className="flex w-full justify-end sm:gap-6">
          {showBackButton && requiresBackButton(searchParamsObj.get("via")) && (
            <CustomButton
              type="button"
              ariaLabel="Back"
              className="w-1/2 bg-transparent"
              variant="faded"
              size="lg"
              radius="lg"
              onPress={handleBackStep}
              startContent={!isLoading && <ChevronLeftIcon size={24} />}
              isDisabled={isLoading}
            >
              <span>Back</span>
            </CustomButton>
          )}
          <CustomButton
            type="submit"
            ariaLabel="Save"
            className="w-1/2"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            endContent={!isLoading && <ChevronRightIcon size={24} />}
            onPress={(e) => {
              const formElement = e.target as HTMLElement;
              const form = formElement.closest("form");
              if (form) {
                form.dispatchEvent(
                  new Event("submit", { bubbles: true, cancelable: true }),
                );
              }
            }}
          >
            {isLoading ? <>Loading</> : <span>{submitButtonText}</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
