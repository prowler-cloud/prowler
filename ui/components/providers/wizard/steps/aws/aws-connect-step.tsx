"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import {
  ChevronDownIcon,
  CircleAlert,
  KeyRound,
  Loader2,
  ShieldCheck,
} from "lucide-react";
import { useSession } from "next-auth/react";
import { useEffect, useRef, useState } from "react";
import {
  Control,
  FieldValues,
  Resolver,
  UseFormReturn,
  useForm,
  useFormState,
  useWatch,
} from "react-hook-form";

import { RadioCard } from "@/components/providers/radio-card";
import { CredentialsRoleHelper } from "@/components/providers/workflow/credentials-role-helper";
import { WizardInputField } from "@/components/providers/workflow/forms/fields";
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
import { useMountEffect } from "@/hooks/use-mount-effect";
import { PROVIDER_CREDENTIALS_ERROR_MAPPING } from "@/lib/error-mappings";
import { getAWSCredentialsTemplateLinks } from "@/lib/external-urls";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import {
  ACCOUNT_SUBMIT_OUTCOME,
  dispatchProviderFunnel,
  PROVIDER_FUNNEL_STEP,
} from "@/lib/provider-funnel/provider-funnel-events";
import { testProviderConnection } from "@/lib/provider-helpers";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import type { AWSCredentials, AWSCredentialsRole } from "@/types";
import type { AwsConnectDraft } from "@/types/provider-wizard";

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

// What the user typed survives the step unmounting (organizations tab, a step
// back from the launch step) until the wizard closes.
const readDraft = () => useProviderWizardStore.getState().awsConnectDraft;

const initialMethod = (): AwsAccessMethod =>
  readDraft()?.method === AWS_ACCESS_METHOD.CREDENTIALS
    ? AWS_ACCESS_METHOD.CREDENTIALS
    : AWS_ACCESS_METHOD.ROLE;

function useDraftValues<T extends FieldValues>(
  form: UseFormReturn<T>,
  key: keyof Pick<AwsConnectDraft, "roleValues" | "keysValues">,
) {
  const values = useWatch({ control: form.control });
  useEffect(() => {
    useProviderWizardStore
      .getState()
      .setAwsConnectDraft({ [key]: values as AwsConnectDraft[typeof key] });
  }, [key, values]);
}

interface AwsConnectStepProps {
  formId: string;
  onConnected: () => void;
  onSelectOrganizations: () => void;
  onUiStateChange: (state: AwsConnectUiState) => void;
}

/** One form to register an AWS account, store its credentials and test the connection. */
export function AwsConnectStep({
  formId,
  onConnected,
  onSelectOrganizations,
  onUiStateChange,
}: AwsConnectStepProps) {
  // Local state needed: the access method only matters until the account is connected.
  const [method, setMethod] = useState<AwsAccessMethod>(initialMethod);
  // Local state needed: the active form reports it so the method cannot change mid-submit.
  const [isBusy, setIsBusy] = useState(false);

  const isRole = method === AWS_ACCESS_METHOD.ROLE;

  const chooseMethod = (next: AwsAccessMethod) => {
    setMethod(next);
    useProviderWizardStore.getState().setAwsConnectDraft({ method: next });
  };

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
          onClick={() => chooseMethod(AWS_ACCESS_METHOD.ROLE)}
        >
          <Badge variant="success" size="sm">
            Recommended
          </Badge>
        </RadioCard>
        <RadioCard
          icon={KeyRound}
          title="Static access keys"
          selected={!isRole}
          disabled={isBusy}
          onClick={() => chooseMethod(AWS_ACCESS_METHOD.CREDENTIALS)}
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
  // Beyond form validity: the role form also needs an account read from the ARN.
  accountResolved?: boolean;
  extraValues?: Record<string, string>;
  onConnected: () => void;
  onBusyChange: (isBusy: boolean) => void;
  onUiStateChange: (state: AwsConnectUiState) => void;
}

const CONNECTION_FAILED_MESSAGE =
  "Prowler could not connect with these credentials. Review them and try again.";

const CONNECTION_UNREACHABLE_MESSAGE =
  "The connection test could not be completed. The account is saved, so you can try again.";

/** Footer label for the one-step form: the test and the retry share the submit. */
const resolveActionLabel = ({
  isTesting,
  isSubmitting,
  hasFailed,
}: {
  isTesting: boolean;
  isSubmitting: boolean;
  hasFailed: boolean;
}) => {
  if (isTesting) return "Testing connection...";
  if (isSubmitting) return "Connecting account...";
  return hasFailed ? "Retry connection" : "Connect account";
};

/** Registers the account, stores its credentials and tests the connection in one submit. */
function useAwsConnectSubmit<T extends FieldValues>({
  form,
  method,
  accountField,
  accountResolved = true,
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
  // Local state needed: the connection test runs inside the submit, and its
  // outcome belongs to this step rather than to any form field.
  const [isTesting, setIsTesting] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  // A hook, not `form.formState.isValid` read inline: the React Compiler keys
  // its memo on the stable `form` object and would freeze a proxy read at false.
  const { isSubmitting, isValid } = useFormState({ control: form.control });
  const canSubmit = isValid && accountResolved;
  const isBusy = isSubmitting || isTesting;
  // Closing the wizard (or switching to organizations) unmounts the step while a
  // test may still be running; its result must not advance a wizard already reset.
  const isActiveRef = useRef(true);
  useMountEffect(() => {
    isActiveRef.current = true;
    return () => {
      isActiveRef.current = false;
    };
  });

  // Same contract ConnectAccountForm uses: the wizard footer lives outside the step.
  // Both callbacks must be stable setters, or this effect would loop.
  useEffect(() => {
    onBusyChange(isBusy);
    onUiStateChange({
      showBack: true,
      showAction: true,
      actionLabel: resolveActionLabel({
        isTesting,
        isSubmitting,
        hasFailed: connectionError !== null,
      }),
      actionDisabled: !canSubmit || isBusy,
      isLoading: isBusy,
    });
  }, [
    canSubmit,
    connectionError,
    isBusy,
    isSubmitting,
    isTesting,
    onBusyChange,
    onUiStateChange,
  ]);

  // A past failure must not sit above the field the user is already correcting.
  useEffect(() => {
    if (connectionError === null) return;
    const subscription = form.watch(() => setConnectionError(null));
    return () => subscription.unsubscribe();
  }, [connectionError, form]);

  const onSubmit = form.handleSubmit(async (values) => {
    setConnectionError(null);
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

    // The account stays registered whatever the test says; resubmitting edits it
    // in place. Task polling rejects on a 5xx, so the flag has to be cleared in a
    // finally or the step would stay stuck on "Testing connection...".
    let connected = false;
    setIsTesting(true);
    try {
      const connection = await testProviderConnection(result.providerId);
      connected = connection.connected;
      if (!connected) {
        setConnectionError(connection.error || CONNECTION_FAILED_MESSAGE);
      }
    } catch {
      setConnectionError(CONNECTION_UNREACHABLE_MESSAGE);
    } finally {
      setIsTesting(false);
    }

    if (connected && isActiveRef.current) onConnected();
  });

  return { onSubmit, isTesting, connectionError };
}

/** Progress line while the test runs, or the API's reason once it is refused. */
function ConnectionFeedback({
  isTesting,
  error,
}: {
  isTesting: boolean;
  error: string | null;
}) {
  const alertRef = useRef<HTMLDivElement>(null);

  // The form scrolls inside the modal and the action button sits outside it, so
  // an error raised from the footer can land above the fold.
  useEffect(() => {
    if (!error) return;
    // Guarded: jsdom has no scrollIntoView, and a throw here would unmount the step.
    alertRef.current?.scrollIntoView?.({ block: "start", behavior: "smooth" });
  }, [error]);

  if (isTesting) {
    return (
      <p
        role="status"
        className="text-text-neutral-secondary flex items-center gap-2 text-sm"
      >
        <Loader2 aria-hidden className="size-4 animate-spin" />
        Testing the connection. This usually takes a few seconds.
      </p>
    );
  }

  if (!error) return null;

  return (
    <div
      ref={alertRef}
      role="alert"
      className="border-border-error flex items-start gap-3 rounded-lg border p-4"
    >
      <CircleAlert
        aria-hidden
        className="text-text-error-primary size-5 shrink-0"
      />
      <p className="text-text-error-primary min-w-0 text-sm break-words">
        {error}
      </p>
    </div>
  );
}

function AwsRoleConnectForm({
  formId,
  onConnected,
  onBusyChange,
  onUiStateChange,
}: ConnectFormProps) {
  const { data: session } = useSession();
  const externalId = session?.tenantId ?? "";

  const form = useForm<AwsRoleConnectValues>({
    resolver: zodResolver(
      awsRoleConnectSchema,
    ) as unknown as Resolver<AwsRoleConnectValues>,
    mode: "onChange",
    defaultValues: {
      [ProviderCredentialFields.PROVIDER_ID]: "",
      [ProviderCredentialFields.PROVIDER_TYPE]: "aws",
      [ProviderCredentialFields.PROVIDER_ALIAS]: "",
      // The role is assumed with Prowler's own credentials (Cloud's identity or the
      // host's AWS SDK chain); static keys are a method of their own, never mixed in.
      [ProviderCredentialFields.CREDENTIALS_TYPE]:
        ProviderCredentialFields.CREDENTIALS_TYPE_AWS,
      [ProviderCredentialFields.ROLE_ARN]: "",
      [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: "",
      [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: "",
      [ProviderCredentialFields.AWS_SESSION_TOKEN]: "",
      [ProviderCredentialFields.ROLE_SESSION_NAME]: "",
      [ProviderCredentialFields.SESSION_DURATION]: "3600",
      ...readDraft()?.roleValues,
    },
  });
  useDraftValues(form, "roleValues");

  const roleArn = useWatch({
    control: form.control,
    name: ProviderCredentialFields.ROLE_ARN,
  });
  const detectedAccountId = parseAwsAccountIdFromRoleArn(roleArn ?? "");

  const { onSubmit, isTesting, connectionError } = useAwsConnectSubmit({
    form,
    method: AWS_ACCESS_METHOD.ROLE,
    accountField: ProviderCredentialFields.ROLE_ARN,
    accountResolved: detectedAccountId !== null,
    // The external id is the tenant's, never user input, so it joins at submit time.
    extraValues: { [ProviderCredentialFields.EXTERNAL_ID]: externalId },
    onConnected,
    onBusyChange,
    onUiStateChange,
  });

  // One template for every build: self-hosted users set the account that assumes
  // the role, so the AccountId parameter must stay editable in the console.
  const templateLinks = getAWSCredentialsTemplateLinks(externalId);
  const roleControl = form.control as unknown as Control<AWSCredentialsRole>;

  return (
    <Form {...form}>
      <form id={formId} onSubmit={onSubmit} className="flex flex-col gap-6">
        <ConnectionFeedback isTesting={isTesting} error={connectionError} />

        <section className="flex flex-col gap-4">
          <h4 className="text-sm font-semibold">1. Create the IAM role</h4>
          <CredentialsRoleHelper
            externalId={externalId}
            templateLinks={templateLinks}
          />
        </section>

        <section className="flex flex-col gap-4">
          <h4 className="text-sm font-semibold">2. Paste the role ARN</h4>
          <div className="flex flex-col gap-1.5">
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
          </div>
          <AliasField
            control={form.control as unknown as Control<FieldValues>}
          />
        </section>

        <Collapsible className="flex flex-col gap-4">
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
      ...readDraft()?.keysValues,
    },
  });
  useDraftValues(form, "keysValues");

  const { onSubmit, isTesting, connectionError } = useAwsConnectSubmit({
    form,
    method: AWS_ACCESS_METHOD.CREDENTIALS,
    accountField: ProviderCredentialFields.PROVIDER_UID,
    onConnected,
    onBusyChange,
    onUiStateChange,
  });

  return (
    <Form {...form}>
      <form id={formId} onSubmit={onSubmit} className="flex flex-col gap-4">
        <ConnectionFeedback isTesting={isTesting} error={connectionError} />

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
