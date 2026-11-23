"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { ChevronDownIcon } from "lucide-react";
import { useSession } from "next-auth/react";
import {
  Control,
  FieldValues,
  Resolver,
  useForm,
  useWatch,
} from "react-hook-form";

import { CredentialsRoleHelper } from "@/components/providers/workflow/credentials-role-helper";
import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { AwsRoleOptionalFields } from "@/components/providers/workflow/forms/select-credentials-type/aws/credentials-type/aws-role-optional-fields";
import { AWSStaticCredentialsForm } from "@/components/providers/workflow/forms/select-credentials-type/aws/credentials-type/aws-static-credentials-form";
import { Button } from "@/components/shadcn/button/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/shadcn/collapsible";
import { Form } from "@/components/shadcn/form";
import { getAWSCredentialsTemplateLinks } from "@/lib/external-urls";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import type { AWSCredentials, AWSCredentialsRole } from "@/types";

import { AliasField } from "../connect/alias-field";
import { ConnectionFeedback } from "../connect/connection-feedback";
import type { ConnectFormProps } from "../connect/types";
import { readDraftValues, useDraftValues } from "../connect/use-connect-draft";
import { useConnectSubmit } from "../connect/use-connect-submit";

import {
  awsKeysConnectSchema,
  type AwsKeysConnectValues,
  awsRoleConnectSchema,
  type AwsRoleConnectValues,
} from "./aws-connect.schema";
import { parseAwsAccountIdFromRoleArn } from "./aws-role-arn";
import { AWS_ACCESS_METHOD } from "./types";

const lockedUid = () => useProviderWizardStore.getState().providerUid;

/** IAM role: the account is read from the role ARN. */
export function AwsRoleConnectForm({
  formId,
  locked,
  ...connectProps
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
      ...readDraftValues("aws", AWS_ACCESS_METHOD.ROLE),
    },
  });
  useDraftValues(form, "aws", AWS_ACCESS_METHOD.ROLE);

  const roleArn = useWatch({
    control: form.control,
    name: ProviderCredentialFields.ROLE_ARN,
  });
  const detectedAccountId = parseAwsAccountIdFromRoleArn(roleArn ?? "");

  const { onSubmit, isTesting, connectionError, connectionPending } =
    useConnectSubmit({
      ...connectProps,
      form,
      locked,
      providerType: "aws",
      method: AWS_ACCESS_METHOD.ROLE,
      accountField: ProviderCredentialFields.ROLE_ARN,
      accountResolved: detectedAccountId !== null,
      resolveIdentity: (values) => ({
        uid: parseAwsAccountIdFromRoleArn(
          values[ProviderCredentialFields.ROLE_ARN] ?? "",
        ),
        alias: locked
          ? undefined
          : (values[ProviderCredentialFields.PROVIDER_ALIAS] ?? ""),
      }),
      // The external id is the tenant's, never user input, so it joins at submit time.
      extraValues: { [ProviderCredentialFields.EXTERNAL_ID]: externalId },
    });

  // One template for every build: self-hosted users set the account that assumes
  // the role, so the AccountId parameter must stay editable in the console.
  const templateLinks = getAWSCredentialsTemplateLinks(externalId);
  const roleControl = form.control as unknown as Control<AWSCredentialsRole>;

  return (
    <Form {...form}>
      <form id={formId} onSubmit={onSubmit} className="flex flex-col gap-6">
        <ConnectionFeedback
          isTesting={isTesting}
          error={connectionError}
          pending={connectionPending}
        />

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
            {detectedAccountId && !locked && (
              <p className="text-text-success-primary text-xs">
                Account {detectedAccountId} will be added to Prowler.
              </p>
            )}
          </div>
          {!locked && (
            <AliasField
              control={form.control as unknown as Control<FieldValues>}
            />
          )}
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

/** Static access keys: the account id is typed (or fixed when updating). */
export function AwsKeysConnectForm({
  formId,
  locked,
  ...connectProps
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
      ...readDraftValues("aws", AWS_ACCESS_METHOD.CREDENTIALS),
      ...(locked
        ? { [ProviderCredentialFields.PROVIDER_UID]: lockedUid() ?? "" }
        : {}),
    },
  });
  useDraftValues(form, "aws", AWS_ACCESS_METHOD.CREDENTIALS);

  const { onSubmit, isTesting, connectionError, connectionPending } =
    useConnectSubmit({
      ...connectProps,
      form,
      locked,
      providerType: "aws",
      method: AWS_ACCESS_METHOD.CREDENTIALS,
      accountField: ProviderCredentialFields.PROVIDER_UID,
      resolveIdentity: (values) => ({
        uid: values[ProviderCredentialFields.PROVIDER_UID]?.trim() || null,
        alias: locked
          ? undefined
          : (values[ProviderCredentialFields.PROVIDER_ALIAS] ?? ""),
      }),
    });

  return (
    <Form {...form}>
      <form id={formId} onSubmit={onSubmit} className="flex flex-col gap-4">
        <ConnectionFeedback
          isTesting={isTesting}
          error={connectionError}
          pending={connectionPending}
        />

        {!locked && (
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
        )}
        <AWSStaticCredentialsForm
          control={form.control as unknown as Control<AWSCredentials>}
        />
        {!locked && (
          <AliasField
            control={form.control as unknown as Control<FieldValues>}
          />
        )}
      </form>
    </Form>
  );
}
