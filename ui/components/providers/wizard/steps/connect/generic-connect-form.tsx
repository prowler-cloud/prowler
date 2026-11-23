"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useSession } from "next-auth/react";
import {
  Control,
  FieldValues,
  Resolver,
  useForm,
  useWatch,
} from "react-hook-form";

import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { Form } from "@/components/shadcn/form";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { addProviderFormSchema } from "@/types/formSchemas";
import type { KnownProviderType } from "@/types/providers";

import { AliasField } from "./alias-field";
import { getUidFieldDetails } from "./connect-methods";
import { UID_MIRROR_FIELD } from "./connect-provider-account";
import { ConnectionFeedback } from "./connection-feedback";
import {
  getCredentialsFormDefaults,
  getCredentialsFormSchema,
} from "./credentials-form-config";
import { ProviderCredentialsFields } from "./provider-credentials-fields";
import type { ConnectFormProps } from "./types";
import { readDraftValues, useDraftValues } from "./use-connect-draft";
import { useConnectSubmit } from "./use-connect-submit";

interface GenericConnectFormProps extends ConnectFormProps {
  providerType: KnownProviderType;
  method: string | null;
}

/** Account and credentials of a built-in provider in one form. */
export function GenericConnectForm({
  providerType,
  method,
  formId,
  locked,
  ...connectProps
}: GenericConnectFormProps) {
  const { data: session } = useSession();
  const storedUid = useProviderWizardStore.getState().providerUid ?? "";
  const uidField = getUidFieldDetails(providerType);
  // Secrets that repeat the account id: their hidden field follows the uid above.
  const mirrorField = UID_MIRROR_FIELD[providerType];

  const credentialsSchema = getCredentialsFormSchema(providerType, method);
  // Updating keeps the account as it is: only the credentials are validated.
  const schema = locked
    ? credentialsSchema
    : addProviderFormSchema.and(credentialsSchema);
  const validate = zodResolver(schema) as unknown as Resolver<FieldValues>;
  const resolver: Resolver<FieldValues> = (values, context, options) =>
    validate(
      mirrorField
        ? {
            ...values,
            [mirrorField]: locked
              ? storedUid
              : values[ProviderCredentialFields.PROVIDER_UID],
          }
        : values,
      context,
      options,
    );

  const form = useForm<FieldValues>({
    resolver,
    mode: "onChange",
    defaultValues: {
      ...getCredentialsFormDefaults(providerType, method, {
        providerUid: locked ? storedUid : "",
        externalId: session?.tenantId ?? "",
      }),
      [ProviderCredentialFields.PROVIDER_UID]: locked ? storedUid : "",
      [ProviderCredentialFields.PROVIDER_ALIAS]: "",
      ...readDraftValues(providerType, method),
      // The draft never overrides what identifies the account being connected.
      [ProviderCredentialFields.PROVIDER_TYPE]: providerType,
    },
  });
  useDraftValues(form, providerType, method);

  const typedUid = useWatch({
    control: form.control,
    name: ProviderCredentialFields.PROVIDER_UID,
  }) as string | undefined;

  const { onSubmit, isTesting, connectionError, connectionPending } =
    useConnectSubmit({
      ...connectProps,
      form,
      locked,
      providerType,
      method,
      accountField: ProviderCredentialFields.PROVIDER_UID,
      resolveIdentity: (values) => ({
        uid: locked
          ? storedUid || null
          : String(
              values[ProviderCredentialFields.PROVIDER_UID] ?? "",
            ).trim() || null,
        alias: locked
          ? undefined
          : String(values[ProviderCredentialFields.PROVIDER_ALIAS] ?? ""),
      }),
    });

  const control = form.control as Control<FieldValues>;

  return (
    <Form {...form}>
      <form id={formId} onSubmit={onSubmit} className="flex flex-col gap-4">
        <ConnectionFeedback
          isTesting={isTesting}
          error={connectionError}
          pending={connectionPending}
        />

        {!locked && (
          <div className="grid gap-4 sm:grid-cols-2">
            <WizardInputField
              control={control}
              name={ProviderCredentialFields.PROVIDER_UID}
              type="text"
              label={uidField.label}
              labelPlacement="inside"
              placeholder={uidField.placeholder}
              variant="bordered"
              isRequired
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
            <AliasField control={control} />
          </div>
        )}

        <ProviderCredentialsFields
          providerType={providerType}
          via={method}
          control={control}
          providerUid={locked ? storedUid : typedUid}
        />
      </form>
    </Form>
  );
}
