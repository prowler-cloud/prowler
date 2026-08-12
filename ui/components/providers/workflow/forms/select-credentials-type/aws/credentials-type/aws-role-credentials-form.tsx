import { useEffect, useState } from "react";
import { Control, UseFormSetValue, useWatch } from "react-hook-form";

import { CredentialsRoleHelper } from "@/components/providers/workflow";
import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Checkbox } from "@/components/shadcn/checkbox/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { Separator } from "@/components/shadcn/separator/separator";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { isCloud } from "@/lib/shared/env";
import { AWSCredentialsRole, AWSRoleChainStep } from "@/types";
import { IntegrationType } from "@/types/integrations";

const MAX_CHAIN_STEPS = 10;

const emptyChainStep = (): AWSRoleChainStep => ({
  role_arn: "",
  external_id: "",
  role_session_name: "",
  session_duration: "",
  sts_region: "",
});

export const AWSRoleCredentialsForm = ({
  control,
  setValue,
  externalId,
  templateLinks,
  type = "providers",
  integrationType,
}: {
  control: Control<AWSCredentialsRole>;
  setValue: UseFormSetValue<AWSCredentialsRole>;
  externalId: string;
  templateLinks: {
    cloudformation: string;
    cloudformationQuickLink: string;
    terraform: string;
  };
  type?: "providers" | "integrations";
  integrationType?: IntegrationType;
}) => {
  const isCloudEnv = isCloud();
  const defaultCredentialsType = isCloudEnv
    ? "aws-sdk-default"
    : "access-secret-key";

  const credentialsType = useWatch({
    control,
    name: ProviderCredentialFields.CREDENTIALS_TYPE,
    defaultValue: defaultCredentialsType,
  });

  const [showOptionalRole, setShowOptionalRole] = useState(false);
  const [chainSteps, setChainSteps] = useState<AWSRoleChainStep[]>([]);
  const [showChain, setShowChain] = useState(false);

  const showRoleSection =
    type === "providers" ||
    (isCloudEnv && credentialsType === "aws-sdk-default") ||
    showOptionalRole;

  // Sync chain steps to a hidden form field as JSON
  useEffect(() => {
    if (chainSteps.length > 0) {
      setValue(
        ProviderCredentialFields.ROLE_CHAIN_JSON as any,
        JSON.stringify(chainSteps),
      );
    } else {
      setValue(ProviderCredentialFields.ROLE_CHAIN_JSON as any, "");
    }
  }, [chainSteps, setValue]);

  // Track role section visibility and ensure external_id is set
  useEffect(() => {
    // Set show_role_section for validation
    setValue("show_role_section" as any, showRoleSection);

    // When role section is shown, ensure external_id is set
    // This handles both initial mount and when the section becomes visible
    if (showRoleSection && externalId) {
      setValue(ProviderCredentialFields.EXTERNAL_ID, externalId, {
        shouldValidate: false,
        shouldDirty: false,
      });
    }
  }, [showRoleSection, setValue, externalId]);

  const addChainStep = () => {
    if (chainSteps.length < MAX_CHAIN_STEPS) {
      setChainSteps([...chainSteps, emptyChainStep()]);
    }
  };

  const removeChainStep = (index: number) => {
    setChainSteps(chainSteps.filter((_, i) => i !== index));
  };

  const updateChainStep = (
    index: number,
    field: keyof AWSRoleChainStep,
    value: string,
  ) => {
    const updated = [...chainSteps];
    updated[index] = { ...updated[index], [field]: value };
    setChainSteps(updated);
  };

  return (
    <>
      <div className="flex flex-col">
        {type === "providers" && (
          <div className="text-md text-text-neutral-primary leading-9 font-bold">
            Connect assuming IAM Role
          </div>
        )}
      </div>

      <span className="text-text-neutral-tertiary text-xs font-bold">
        Specify which AWS credentials to use
      </span>

      <div className="mb-4 flex flex-col gap-1.5">
        <Select
          value={credentialsType || defaultCredentialsType}
          onValueChange={(value) => {
            setValue(
              ProviderCredentialFields.CREDENTIALS_TYPE,
              value as "aws-sdk-default" | "access-secret-key",
            );
          }}
        >
          <SelectTrigger>
            <SelectValue placeholder="Select credentials type" />
          </SelectTrigger>
          <SelectContent className="z-[60]">
            <SelectItem value="aws-sdk-default">
              <div className="flex w-full items-center justify-between">
                <span>
                  {isCloudEnv
                    ? "Prowler Cloud will assume your IAM role"
                    : "AWS SDK Default"}
                </span>
                {isCloudEnv && (
                  <Badge variant="tag" className="ml-2">
                    Recommended
                  </Badge>
                )}
              </div>
            </SelectItem>
            <SelectItem value="access-secret-key">
              <div className="flex w-full items-center justify-between">
                <span>Access & Secret Key</span>
              </div>
            </SelectItem>
          </SelectContent>
        </Select>
      </div>

      {credentialsType === "access-secret-key" && (
        <>
          <WizardInputField
            control={control}
            name={ProviderCredentialFields.AWS_ACCESS_KEY_ID}
            type="password"
            label="AWS Access Key ID"
            labelPlacement="inside"
            placeholder="Enter the AWS Access Key ID"
            variant="bordered"
            isRequired
          />
          <WizardInputField
            control={control}
            name={ProviderCredentialFields.AWS_SECRET_ACCESS_KEY}
            type="password"
            label="AWS Secret Access Key"
            labelPlacement="inside"
            placeholder="Enter the AWS Secret Access Key"
            variant="bordered"
            isRequired
          />
          <WizardInputField
            control={control}
            name={ProviderCredentialFields.AWS_SESSION_TOKEN}
            type="password"
            label="AWS Session Token (optional)"
            labelPlacement="inside"
            placeholder="Enter the AWS Session Token"
            variant="bordered"
            isRequired={false}
          />
        </>
      )}
      <Separator />

      {type === "providers" ? (
        <span className="text-text-neutral-tertiary text-xs font-bold">
          Assume Role
        </span>
      ) : (
        <div className="flex items-center justify-between">
          <span className="text-text-neutral-tertiary text-xs font-bold">
            {isCloudEnv && credentialsType === "aws-sdk-default"
              ? "Adding a role is required"
              : "Optionally add a role"}
          </span>
          <Checkbox
            checked={showRoleSection}
            onCheckedChange={(checked) => setShowOptionalRole(Boolean(checked))}
            disabled={isCloudEnv && credentialsType === "aws-sdk-default"}
            aria-label="Optionally add a role"
          />
        </div>
      )}

      {showRoleSection && (
        <>
          <CredentialsRoleHelper
            externalId={externalId}
            templateLinks={templateLinks}
            integrationType={integrationType}
          />

          <Separator />

          <WizardInputField
            control={control}
            name={ProviderCredentialFields.ROLE_ARN}
            type="text"
            label="Role ARN"
            labelPlacement="inside"
            placeholder="Enter the Role ARN"
            variant="bordered"
            isRequired={showRoleSection}
          />
          <WizardInputField
            control={control}
            name={ProviderCredentialFields.EXTERNAL_ID}
            type="text"
            label="External ID"
            labelPlacement="inside"
            placeholder={externalId}
            variant="bordered"
            defaultValue={externalId}
            isDisabled
            isRequired
          />

          <span className="text-text-neutral-tertiary text-xs">
            Optional fields
          </span>
          <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
            <WizardInputField
              control={control}
              name={ProviderCredentialFields.ROLE_SESSION_NAME}
              type="text"
              label="Role session name"
              labelPlacement="inside"
              placeholder="Enter the role session name"
              variant="bordered"
              isRequired={false}
            />
            <WizardInputField
              control={control}
              name={ProviderCredentialFields.SESSION_DURATION}
              type="number"
              label="Session duration (seconds)"
              labelPlacement="inside"
              placeholder="Enter the session duration (default: 3600 seconds)"
              variant="bordered"
              isRequired={false}
            />
          </div>

          <Separator />

          <div className="flex items-center justify-between">
            <div className="flex flex-col">
              <span className="text-text-neutral-tertiary text-xs font-bold">
                Ordered Role Chain
              </span>
              <span className="text-text-neutral-tertiary text-xs">
                Define additional hops for multi-step role assumption
              </span>
            </div>
            <Checkbox
              checked={showChain}
              onCheckedChange={(checked) => setShowChain(Boolean(checked))}
              aria-label="Enable ordered role chain"
            />
          </div>

          {showChain && (
            <div className="flex flex-col gap-4 rounded-md border p-4">
              <span className="text-text-neutral-secondary text-xs">
                Each step defines one{" "}
                <code className="text-xs">sts:AssumeRole</code> hop. The final
                step&apos;s role is used for scanning. Leave the single Role
                ARN above empty when using a chain.
              </span>

              {chainSteps.map((step, index) => (
                <div
                  key={index}
                  className="flex flex-col gap-2 rounded-md border p-3"
                >
                  <div className="flex items-center justify-between">
                    <Badge variant="tag">Hop {index + 1}</Badge>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => removeChainStep(index)}
                      className="h-6 px-2 text-xs"
                    >
                      Remove
                    </Button>
                  </div>
                  <input
                    type="text"
                    placeholder="Role ARN (required)"
                    value={step.role_arn}
                    onChange={(e) =>
                      updateChainStep(index, "role_arn", e.target.value)
                    }
                    className="border-input bg-background ring-offset-background placeholder:text-muted-foreground focus-visible:ring-ring flex h-10 w-full rounded-md border px-3 py-2 text-sm file:border-0 file:bg-transparent file:text-sm file:font-medium focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
                  />
                  <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                    <input
                      type="text"
                      placeholder="External ID (optional)"
                      value={step.external_id || ""}
                      onChange={(e) =>
                        updateChainStep(index, "external_id", e.target.value)
                      }
                      className="border-input bg-background ring-offset-background placeholder:text-muted-foreground focus-visible:ring-ring flex h-10 w-full rounded-md border px-3 py-2 text-sm file:border-0 file:bg-transparent file:text-sm file:font-medium focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
                    />
                    <input
                      type="text"
                      placeholder="Role session name (optional)"
                      value={step.role_session_name || ""}
                      onChange={(e) =>
                        updateChainStep(
                          index,
                          "role_session_name",
                          e.target.value,
                        )
                      }
                      className="border-input bg-background ring-offset-background placeholder:text-muted-foreground focus-visible:ring-ring flex h-10 w-full rounded-md border px-3 py-2 text-sm file:border-0 file:bg-transparent file:text-sm file:font-medium focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
                    />
                  </div>
                  <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                    <input
                      type="number"
                      placeholder="Session duration (default: 3600)"
                      value={step.session_duration || ""}
                      onChange={(e) =>
                        updateChainStep(
                          index,
                          "session_duration",
                          e.target.value,
                        )
                      }
                      className="border-input bg-background ring-offset-background placeholder:text-muted-foreground focus-visible:ring-ring flex h-10 w-full rounded-md border px-3 py-2 text-sm file:border-0 file:bg-transparent file:text-sm file:font-medium focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
                    />
                    <input
                      type="text"
                      placeholder="STS region (default: us-east-1)"
                      value={step.sts_region || ""}
                      onChange={(e) =>
                        updateChainStep(index, "sts_region", e.target.value)
                      }
                      className="border-input bg-background ring-offset-background placeholder:text-muted-foreground focus-visible:ring-ring flex h-10 w-full rounded-md border px-3 py-2 text-sm file:border-0 file:bg-transparent file:text-sm file:font-medium focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
                    />
                  </div>
                </div>
              ))}

              {chainSteps.length < MAX_CHAIN_STEPS && (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={addChainStep}
                  className="w-fit"
                >
                  Add Chain Step
                </Button>
              )}

              {chainSteps.length >= MAX_CHAIN_STEPS && (
                <span className="text-xs text-orange-500">
                  Maximum of {MAX_CHAIN_STEPS} chain steps reached.
                </span>
              )}
            </div>
          )}

          {/* Hidden field to store chain as JSON */}
          <input
            type="hidden"
            name={ProviderCredentialFields.ROLE_CHAIN_JSON}
            value={JSON.stringify(chainSteps)}
          />
        </>
      )}
    </>
  );
};
