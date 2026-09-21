"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { ChevronDownIcon, KeyRound, ShieldCheck } from "lucide-react";
import { useSession } from "next-auth/react";
import { useEffect, useState } from "react";
import {
  Control,
  FieldValues,
  Resolver,
  UseFormReturn,
  UseFormSetValue,
  useForm,
  useWatch,
} from "react-hook-form";

import { RadioCard } from "@/components/providers/radio-card";
import { CredentialsRoleHelper } from "@/components/providers/workflow/credentials-role-helper";
import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { AwsRoleCredentialsSource } from "@/components/providers/workflow/forms/select-credentials-type/aws/credentials-type/aws-role-credentials-source";
import { AwsRoleOptionalFields } from "@/components/providers/workflow/forms/select-credentials-type/aws/credentials-type/aws-role-optional-fields";
import { AWSStaticCredentialsForm } from "@/components/providers/workflow/forms/select-credentials-type/aws/credentials-type/aws-static-credentials-form";
import { ProviderTitleDocs } from "@/components/providers/workflow/provider-title-docs";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/shadcn/collapsible";
import { Form } from "@/components/shadcn/form";
import { useFormServerErrors } from "@/hooks/use-form-server-errors";
import { PROVIDER_CREDENTIALS_ERROR_MAPPING } from "@/lib/error-mappings";
import {
  getAWSCredentialsTemplateLinks,
  getAWSQuickOnboardingTemplateLinks,
} from "@/lib/external-urls";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import {
  ACCOUNT_SUBMIT_OUTCOME,
  dispatchProviderFunnel,
  PROVIDER_FUNNEL_STEP,
} from "@/lib/provider-funnel/provider-funnel-events";
import { isCloud } from "@/lib/shared/env";
import type { AWSCredentials, AWSCredentialsRole } from "@/types";

import {
  awsKeysConnectSchema,
  type AwsKeysConnectValues,
  awsRoleConnectSchema,
  type AwsRoleConnectValues,
} from "./aws-connect.schema";
import {
  AWS_ONBOARDING_METHOD,
  AwsOnboardingMethodTabs,
} from "./aws-onboarding-method-tabs";
import { parseAwsAccountIdFromRoleArn } from "./aws-role-arn";
import {
  AWS_UID_ERROR_POINTER,
  connectAwsAccount,
} from "./connect-aws-account";
import {
  AWS_ACCESS_METHOD,
  type AwsAccessMethod,
  type AwsConnectUiState,
} from "./types";

const ALIAS_ERROR_POINTER = "/data/attributes/alias";
const UNIQUE_TOGETHER_ERROR_POINTER = "/data/attributes/__all__";

interface AwsConnectStepProps {
  formId: string;
  onConnected: () => void;
  onSelectOrganizations: () => void;
  onUiStateChange: (state: AwsConnectUiState) => void;
}

/** One form to register an AWS account and store its credentials. */
export function AwsConnectStep({
  formId,
  onConnected,
  onSelectOrganizations,
  onUiStateChange,
}: AwsConnectStepProps) {
  // Local state needed: the access method only matters until the account is connected.
  const [method, setMethod] = useState<AwsAccessMethod>(AWS_ACCESS_METHOD.ROLE);
  // Local state needed: the active form reports it so the method cannot change mid-submit.
  const [isBusy, setIsBusy] = useState(false);

  const isRole = method === AWS_ACCESS_METHOD.ROLE;

  return (
    <div className="flex flex-col gap-6">
      <ProviderTitleDocs providerType="aws" />

      <AwsOnboardingMethodTabs
        value={AWS_ONBOARDING_METHOD.SINGLE}
        onSelectOrganizations={onSelectOrganizations}
      />

      <div
        role="radiogroup"
        aria-label="AWS access method"
        className="flex flex-col gap-3"
      >
        <p className="text-text-neutral-secondary text-sm">
          Choose how Prowler should access your account.
        </p>
        <RadioCard
          icon={ShieldCheck}
          title="IAM Role"
          selected={isRole}
          disabled={isBusy}
          onClick={() => setMethod(AWS_ACCESS_METHOD.ROLE)}
        >
          <Badge variant="success" size="sm">
            Recommended
          </Badge>
        </RadioCard>
        <RadioCard
          icon={KeyRound}
          title="Access keys"
          selected={!isRole}
          disabled={isBusy}
          onClick={() => setMethod(AWS_ACCESS_METHOD.CREDENTIALS)}
        />
      </div>

      {isRole ? (
        <AwsRoleConnectForm
          formId={formId}
          onConnected={onConnected}
          onBusyChange={setIsBusy}
          onUiStateChange={onUiStateChange}
        />
      ) : (
        <AwsKeysConnectForm
          formId={formId}
          onConnected={onConnected}
          onBusyChange={setIsBusy}
          onUiStateChange={onUiStateChange}
        />
      )}
    </div>
  );
}

interface ConnectFormProps
  extends Pick<
    AwsConnectStepProps,
    "formId" | "onConnected" | "onUiStateChange"
  > {
  onBusyChange: (isBusy: boolean) => void;
}

interface UseAwsConnectSubmitOptions<T extends FieldValues> {
  form: UseFormReturn<T>;
  method: AwsAccessMethod;
  // The field an account-level API error belongs to for this method.
  accountField: string;
  canSubmit: boolean;
  extraValues?: Record<string, string>;
  onConnected: () => void;
  onBusyChange: (isBusy: boolean) => void;
  onUiStateChange: (state: AwsConnectUiState) => void;
}

function useAwsConnectSubmit<T extends FieldValues>({
  form,
  method,
  accountField,
  canSubmit,
  extraValues,
  onConnected,
  onBusyChange,
  onUiStateChange,
}: UseAwsConnectSubmitOptions<T>) {
  const { handleServerResponse } = useFormServerErrors(form, {
    ...PROVIDER_CREDENTIALS_ERROR_MAPPING,
    [AWS_UID_ERROR_POINTER]: accountField,
    [UNIQUE_TOGETHER_ERROR_POINTER]: accountField,
    [ALIAS_ERROR_POINTER]: ProviderCredentialFields.PROVIDER_ALIAS,
  });
  const isSubmitting = form.formState.isSubmitting;

  // Same contract ConnectAccountForm uses: the wizard footer lives outside the step.
  // Both callbacks must be stable setters, or this effect would loop.
  useEffect(() => {
    onBusyChange(isSubmitting);
    onUiStateChange({
      showBack: true,
      showAction: true,
      actionLabel: isSubmitting ? "Connecting account..." : "Connect account",
      actionDisabled: !canSubmit || isSubmitting,
      isLoading: isSubmitting,
    });
  }, [canSubmit, isSubmitting, onBusyChange, onUiStateChange]);

  return form.handleSubmit(async (values) => {
    const result = await connectAwsAccount({
      method,
      values: { ...values, ...extraValues },
    });
    dispatchProviderFunnel({
      step: PROVIDER_FUNNEL_STEP.ACCOUNT_SUBMITTED,
      providerType: "aws",
      via: method,
      outcome: result.ok
        ? ACCOUNT_SUBMIT_OUTCOME.SUCCESS
        : ACCOUNT_SUBMIT_OUTCOME.ERROR,
    });
    if (!result.ok) {
      // Maps API pointers onto the form's fields; anything unmapped becomes a toast.
      handleServerResponse({ errors: result.errors });
      return;
    }
    onConnected();
  });
}

function AwsRoleConnectForm({
  formId,
  onConnected,
  onBusyChange,
  onUiStateChange,
}: ConnectFormProps) {
  const { data: session } = useSession();
  const externalId = session?.tenantId ?? "";
  const isCloudEnv = isCloud();
  const defaultCredentialsType = isCloudEnv
    ? ProviderCredentialFields.CREDENTIALS_TYPE_AWS
    : ProviderCredentialFields.CREDENTIALS_TYPE_ACCESS_SECRET_KEY;

  const form = useForm<AwsRoleConnectValues>({
    resolver: zodResolver(
      awsRoleConnectSchema,
    ) as unknown as Resolver<AwsRoleConnectValues>,
    mode: "onChange",
    defaultValues: {
      [ProviderCredentialFields.PROVIDER_ID]: "",
      [ProviderCredentialFields.PROVIDER_TYPE]: "aws",
      [ProviderCredentialFields.PROVIDER_ALIAS]: "",
      [ProviderCredentialFields.CREDENTIALS_TYPE]: defaultCredentialsType,
      [ProviderCredentialFields.ROLE_ARN]: "",
      [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: "",
      [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: "",
      [ProviderCredentialFields.AWS_SESSION_TOKEN]: "",
      [ProviderCredentialFields.ROLE_SESSION_NAME]: "",
      [ProviderCredentialFields.SESSION_DURATION]: "3600",
    },
  });

  const roleArn = useWatch({
    control: form.control,
    name: ProviderCredentialFields.ROLE_ARN,
  });
  const credentialsType = useWatch({
    control: form.control,
    name: ProviderCredentialFields.CREDENTIALS_TYPE,
  });
  const detectedAccountId = parseAwsAccountIdFromRoleArn(roleArn ?? "");

  const onSubmit = useAwsConnectSubmit({
    form,
    method: AWS_ACCESS_METHOD.ROLE,
    accountField: ProviderCredentialFields.ROLE_ARN,
    canSubmit: form.formState.isValid && detectedAccountId !== null,
    // The external id is the tenant's, never user input, so it joins at submit time.
    extraValues: { [ProviderCredentialFields.EXTERNAL_ID]: externalId },
    onConnected,
    onBusyChange,
    onUiStateChange,
  });

  const templateLinks = isCloudEnv
    ? getAWSQuickOnboardingTemplateLinks(externalId)
    : getAWSCredentialsTemplateLinks(externalId);
  const roleControl = form.control as unknown as Control<AWSCredentialsRole>;

  return (
    <Form {...form}>
      <form id={formId} onSubmit={onSubmit} className="flex flex-col gap-6">
        <section className="flex flex-col gap-3">
          <h4 className="text-sm font-semibold">1. Create the IAM role</h4>
          <CredentialsRoleHelper
            externalId={externalId}
            templateLinks={templateLinks}
          />
        </section>

        <section className="flex flex-col gap-3">
          <h4 className="text-sm font-semibold">2. Paste the role ARN</h4>
          <WizardInputField
            control={form.control}
            name={ProviderCredentialFields.ROLE_ARN}
            type="text"
            label="Role ARN"
            labelPlacement="inside"
            placeholder="arn:aws:iam::123456789012:role/ProwlerScan"
            variant="bordered"
            isRequired
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
          {detectedAccountId && (
            <p className="text-text-success-primary text-xs">
              Account {detectedAccountId} will be added to Prowler.
            </p>
          )}
          <AliasField
            control={form.control as unknown as Control<FieldValues>}
          />
        </section>

        <Collapsible defaultOpen={!isCloudEnv} className="flex flex-col gap-4">
          <CollapsibleTrigger asChild>
            <Button
              type="button"
              variant="link"
              size="link-sm"
              className="group h-auto w-fit gap-1 p-0"
            >
              Advanced options
              <ChevronDownIcon className="size-4 transition-transform group-data-[state=open]:rotate-180" />
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="flex flex-col gap-4">
            <AwsRoleCredentialsSource
              control={roleControl}
              setValue={
                form.setValue as unknown as UseFormSetValue<AWSCredentialsRole>
              }
              credentialsType={credentialsType ?? defaultCredentialsType}
              isCloudEnv={isCloudEnv}
            />
            <AwsRoleOptionalFields control={roleControl} />
          </CollapsibleContent>
        </Collapsible>
      </form>
    </Form>
  );
}

function AwsKeysConnectForm({
  formId,
  onConnected,
  onBusyChange,
  onUiStateChange,
}: ConnectFormProps) {
  const form = useForm<AwsKeysConnectValues>({
    resolver: zodResolver(
      awsKeysConnectSchema,
    ) as unknown as Resolver<AwsKeysConnectValues>,
    mode: "onChange",
    defaultValues: {
      [ProviderCredentialFields.PROVIDER_ID]: "",
      [ProviderCredentialFields.PROVIDER_TYPE]: "aws",
      [ProviderCredentialFields.PROVIDER_UID]: "",
      [ProviderCredentialFields.PROVIDER_ALIAS]: "",
      [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: "",
      [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: "",
      [ProviderCredentialFields.AWS_SESSION_TOKEN]: "",
    },
  });

  const onSubmit = useAwsConnectSubmit({
    form,
    method: AWS_ACCESS_METHOD.CREDENTIALS,
    accountField: ProviderCredentialFields.PROVIDER_UID,
    canSubmit: form.formState.isValid,
    onConnected,
    onBusyChange,
    onUiStateChange,
  });

  return (
    <Form {...form}>
      <form id={formId} onSubmit={onSubmit} className="flex flex-col gap-4">
        <WizardInputField
          control={form.control}
          name={ProviderCredentialFields.PROVIDER_UID}
          type="text"
          label="Account ID"
          labelPlacement="inside"
          placeholder="e.g. 123456789012"
          variant="bordered"
          isRequired
          normalizeValue={(value) => value.replace(/\D/g, "").slice(0, 12)}
        />
        <AWSStaticCredentialsForm
          control={form.control as unknown as Control<AWSCredentials>}
        />
        <AliasField control={form.control as unknown as Control<FieldValues>} />
      </form>
    </Form>
  );
}

function AliasField({ control }: { control: Control<FieldValues> }) {
  return (
    <WizardInputField
      control={control}
      name={ProviderCredentialFields.PROVIDER_ALIAS}
      type="text"
      label="Provider alias (optional)"
      labelPlacement="inside"
      placeholder="Enter the provider alias"
      variant="bordered"
      isRequired={false}
    />
  );
}
