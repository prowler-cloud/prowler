import { z } from "zod";

import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import {
  addCredentialsFormSchema,
  addCredentialsRoleFormSchema,
} from "@/types/formSchemas";

const aliasField = {
  [ProviderCredentialFields.PROVIDER_ALIAS]: z.string().trim().optional(),
};

// The shared credential schemas stay the source of truth; the step only adds the
// account fields it collects in the same form.
const hasText = (value: string | undefined) => (value ?? "").trim().length > 0;

// The step never asks which credentials assume the role: filled keys mean static
// keys, empty keys mean the host's own credentials. So they only make sense as a pair.
export const awsRoleConnectSchema = addCredentialsRoleFormSchema("aws")
  .and(z.object(aliasField))
  .superRefine((data, ctx) => {
    // The shared factory infers a union over every provider; read the AWS keys by name.
    const values = data as Partial<Record<string, string>>;
    const hasAccessKey = hasText(
      values[ProviderCredentialFields.AWS_ACCESS_KEY_ID],
    );
    const hasSecret = hasText(
      values[ProviderCredentialFields.AWS_SECRET_ACCESS_KEY],
    );
    if (hasAccessKey === hasSecret) return;
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: hasAccessKey
        ? "AWS Secret Access Key is required."
        : "AWS Access Key ID is required.",
      path: [
        hasAccessKey
          ? ProviderCredentialFields.AWS_SECRET_ACCESS_KEY
          : ProviderCredentialFields.AWS_ACCESS_KEY_ID,
      ],
    });
  });

export const awsKeysConnectSchema = addCredentialsFormSchema("aws").and(
  z.object({
    ...aliasField,
    [ProviderCredentialFields.PROVIDER_UID]: z
      .string()
      .trim()
      .regex(/^\d{12}$/, "AWS Account ID must be exactly 12 digits"),
  }),
);

// The shared schema factories take a plain string, so their inferred type is the
// union of every provider; the step's forms declare the AWS shape explicitly.
interface AwsConnectAccountValues {
  [ProviderCredentialFields.PROVIDER_ID]: string;
  [ProviderCredentialFields.PROVIDER_TYPE]: string;
  [ProviderCredentialFields.PROVIDER_ALIAS]?: string;
}

export interface AwsRoleConnectValues extends AwsConnectAccountValues {
  [ProviderCredentialFields.ROLE_ARN]: string;
  [ProviderCredentialFields.CREDENTIALS_TYPE]?: string;
  [ProviderCredentialFields.AWS_ACCESS_KEY_ID]?: string;
  [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]?: string;
  [ProviderCredentialFields.AWS_SESSION_TOKEN]?: string;
  [ProviderCredentialFields.ROLE_SESSION_NAME]?: string;
  [ProviderCredentialFields.SESSION_DURATION]?: string;
}

export interface AwsKeysConnectValues extends AwsConnectAccountValues {
  [ProviderCredentialFields.PROVIDER_UID]: string;
  [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: string;
  [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: string;
  [ProviderCredentialFields.AWS_SESSION_TOKEN]?: string;
}
