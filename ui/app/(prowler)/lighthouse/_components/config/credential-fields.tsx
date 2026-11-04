import { Controller, type useForm, useWatch } from "react-hook-form";

import {
  BEDROCK_AUTH_METHOD,
  type LighthouseV2ConfigFormValues,
} from "@/app/(prowler)/lighthouse/_lib/config";
import {
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  type LighthouseV2ProviderType,
} from "@/app/(prowler)/lighthouse/_types";
import { Field, FieldError, FieldLabel } from "@/components/shadcn/field/field";
import { Input } from "@/components/shadcn/input/input";
import {
  RadioGroup,
  RadioGroupItem,
} from "@/components/shadcn/radio-group/radio-group";

// Stored secrets are never sent back by the API, so the fields would look
// empty even when a key exists; the masked placeholder stands in for it.
const STORED_SECRET_PLACEHOLDER = "•".repeat(36);

export function CredentialFields({
  control,
  credentialsOptional = false,
  errors,
  hasStoredCredentials = false,
  provider,
  register,
}: {
  control: ReturnType<typeof useForm<LighthouseV2ConfigFormValues>>["control"];
  // Keys may be left blank (Bedrock with the installation's own role).
  credentialsOptional?: boolean;
  errors: ReturnType<
    typeof useForm<LighthouseV2ConfigFormValues>
  >["formState"]["errors"];
  hasStoredCredentials?: boolean;
  provider: LighthouseV2ProviderType;
  register: ReturnType<
    typeof useForm<LighthouseV2ConfigFormValues>
  >["register"];
}) {
  const isBedrock = provider === LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK;
  // The masked placeholder would suggest a key that may not be there: with
  // optional keys a saved configuration may have none, and for Bedrock the
  // API does not say whether access keys or an API key are stored.
  const secretPlaceholder =
    hasStoredCredentials && !credentialsOptional && !isBedrock
      ? STORED_SECRET_PLACEHOLDER
      : undefined;
  const keyLabelSuffix = credentialsOptional ? " (optional)" : "";
  const bedrockAuthMethod = useWatch({ control, name: "bedrockAuthMethod" });
  const usesBedrockApiKey =
    isBedrock && bedrockAuthMethod === BEDROCK_AUTH_METHOD.API_KEY;
  return (
    <div className="grid gap-4">
      {isBedrock && (
        <Field>
          <FieldLabel>Authentication method</FieldLabel>
          <Controller
            control={control}
            name="bedrockAuthMethod"
            render={({ field }) => (
              <RadioGroup
                value={field.value}
                onValueChange={field.onChange}
                orientation="horizontal"
                aria-label="Authentication method"
              >
                <label className="flex items-center gap-2 text-sm">
                  <RadioGroupItem value={BEDROCK_AUTH_METHOD.ACCESS_KEYS} />
                  AWS access keys
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <RadioGroupItem value={BEDROCK_AUTH_METHOD.API_KEY} />
                  Bedrock API key
                </label>
              </RadioGroup>
            )}
          />
        </Field>
      )}

      {(provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI ||
        provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE ||
        usesBedrockApiKey) && (
        <Field>
          <FieldLabel htmlFor="lighthouse-v2-api-key">API key</FieldLabel>
          <Input
            id="lighthouse-v2-api-key"
            type="password"
            autoComplete="off"
            placeholder={secretPlaceholder}
            aria-invalid={Boolean(errors.apiKey)}
            {...register("apiKey")}
          />
          {errors.apiKey?.message && (
            <FieldError>{errors.apiKey.message}</FieldError>
          )}
        </Field>
      )}

      {provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE && (
        <Field>
          <FieldLabel htmlFor="lighthouse-v2-base-url">Base URL</FieldLabel>
          <Input
            id="lighthouse-v2-base-url"
            aria-invalid={Boolean(errors.baseUrl)}
            placeholder="https://llm.example.com/v1"
            {...register("baseUrl")}
          />
          {errors.baseUrl?.message && (
            <FieldError>{errors.baseUrl.message}</FieldError>
          )}
        </Field>
      )}

      {isBedrock && (
        <div className="grid gap-4 md:grid-cols-2">
          {!usesBedrockApiKey && (
            <>
              <Field>
                <FieldLabel htmlFor="lighthouse-v2-access-key">
                  AWS access key ID{keyLabelSuffix}
                </FieldLabel>
                <Input
                  id="lighthouse-v2-access-key"
                  type="password"
                  autoComplete="off"
                  placeholder={secretPlaceholder}
                  aria-invalid={Boolean(errors.awsAccessKeyId)}
                  {...register("awsAccessKeyId")}
                />
                {errors.awsAccessKeyId?.message && (
                  <FieldError>{errors.awsAccessKeyId.message}</FieldError>
                )}
              </Field>

              <Field>
                <FieldLabel htmlFor="lighthouse-v2-secret-key">
                  AWS secret access key{keyLabelSuffix}
                </FieldLabel>
                <Input
                  id="lighthouse-v2-secret-key"
                  type="password"
                  autoComplete="off"
                  placeholder={secretPlaceholder}
                  aria-invalid={Boolean(errors.awsSecretAccessKey)}
                  {...register("awsSecretAccessKey")}
                />
                {errors.awsSecretAccessKey?.message && (
                  <FieldError>{errors.awsSecretAccessKey.message}</FieldError>
                )}
              </Field>
            </>
          )}

          <Field className="md:col-span-2">
            <FieldLabel htmlFor="lighthouse-v2-region">AWS region</FieldLabel>
            <Input
              id="lighthouse-v2-region"
              placeholder="us-east-1"
              aria-invalid={Boolean(errors.awsRegionName)}
              {...register("awsRegionName")}
            />
            {errors.awsRegionName?.message && (
              <FieldError>{errors.awsRegionName.message}</FieldError>
            )}
          </Field>
        </div>
      )}
    </div>
  );
}
