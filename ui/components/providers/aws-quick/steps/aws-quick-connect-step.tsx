"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import {
  ChevronDownIcon,
  ExternalLink,
  KeyRound,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useForm } from "react-hook-form";

import { IdIcon } from "@/components/icons";
import { AWSProviderBadge } from "@/components/icons/providers-badge";
import { RadioCard } from "@/components/providers/radio-card";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "@/components/providers/wizard/steps/footer-controls";
import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { CodeSnippet } from "@/components/shadcn/code-snippet/code-snippet";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/shadcn/collapsible";
import { Form } from "@/components/shadcn/form";
import { Spinner } from "@/components/shadcn/spinner/spinner";

import {
  AWS_ONBOARDING_METHOD,
  AwsOnboardingMethodTabs,
} from "../aws-onboarding-method-tabs";
import {
  awsQuickRoleSchema,
  AwsQuickRoleValues,
  awsQuickStaticSchema,
  AwsQuickStaticValues,
  parseAwsAccountIdFromRoleArn,
} from "../aws-quick.utils";
import {
  AwsQuickConnectField,
  useAwsQuickConnect,
} from "../hooks/use-aws-quick-connect";
import { AWS_QUICK_ACCESS_METHOD, AwsQuickAccessMethod } from "../types";

export const AWS_QUICK_CONNECT_FORM_ID = "aws-quick-connect-form";

interface TemplateLinks {
  cloudformation: string;
  cloudformationQuickLink: string;
  terraform: string;
}

interface AwsQuickConnectStepProps {
  externalId: string;
  templateLinks: TemplateLinks;
  onBack: () => void;
  onSelectOrganizations: () => void;
  onConnected: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

export function AwsQuickConnectStep(props: AwsQuickConnectStepProps) {
  // Local state needed: the access method only matters until the account is connected.
  const [method, setMethod] = useState<AwsQuickAccessMethod>(
    AWS_QUICK_ACCESS_METHOD.ROLE,
  );
  const formProps = { ...props, method, onMethodChange: setMethod };

  return method === AWS_QUICK_ACCESS_METHOD.ROLE ? (
    <RoleConnectForm {...formProps} />
  ) : (
    <StaticConnectForm {...formProps} />
  );
}

interface ConnectFormProps extends AwsQuickConnectStepProps {
  method: AwsQuickAccessMethod;
  onMethodChange: (method: AwsQuickAccessMethod) => void;
}

interface ConnectFooterOptions {
  isConnecting: boolean;
  isValid: boolean;
  onBack: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

function useConnectFooter({
  isConnecting,
  isValid,
  onBack,
  onFooterChange,
}: ConnectFooterOptions) {
  // The modal recreates its callbacks on every render; a ref keeps the effect stable.
  const onBackRef = useRef(onBack);
  onBackRef.current = onBack;

  useEffect(() => {
    onFooterChange({
      showBack: true,
      backLabel: "Back",
      backDisabled: isConnecting,
      onBack: () => onBackRef.current(),
      showAction: true,
      actionLabel: isConnecting ? "Testing connection..." : "Test connection",
      actionLoading: isConnecting,
      actionDisabled: !isValid || isConnecting,
      actionType: WIZARD_FOOTER_ACTION_TYPE.SUBMIT,
      actionFormId: AWS_QUICK_CONNECT_FORM_ID,
    });
  }, [isConnecting, isValid, onFooterChange]);
}

function ConnectingNotice() {
  return (
    <div className="flex min-h-[160px] items-center justify-center">
      <div className="flex items-center gap-3 py-2">
        <Spinner className="size-6" />
        <p className="text-sm font-medium">Testing the connection...</p>
      </div>
    </div>
  );
}

function ConnectionErrorAlert({ message }: { message: string }) {
  return (
    <Alert variant="error">
      <AlertTitle>Prowler could not connect</AlertTitle>
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  );
}

interface AccessMethodPickerProps {
  method: AwsQuickAccessMethod;
  onMethodChange: (method: AwsQuickAccessMethod) => void;
  onSelectOrganizations: () => void;
  disabled: boolean;
}

function AccessMethodPicker({
  method,
  onMethodChange,
  onSelectOrganizations,
  disabled,
}: AccessMethodPickerProps) {
  const isRole = method === AWS_QUICK_ACCESS_METHOD.ROLE;

  return (
    <>
      <div className="flex items-center gap-4">
        <AWSProviderBadge size={32} />
        <h3 className="text-base font-semibold">
          Amazon Web Services (AWS) / Connect account
        </h3>
      </div>

      <AwsOnboardingMethodTabs
        value={AWS_ONBOARDING_METHOD.SINGLE}
        onSelectSingle={() => {}}
        onSelectOrganizations={onSelectOrganizations}
      />

      <div
        role="radiogroup"
        aria-label="AWS access method"
        className="flex flex-col gap-3"
      >
        <p className="text-muted-foreground text-sm">
          Choose how Prowler should access your account.
        </p>
        <RadioCard
          icon={ShieldCheck}
          title="IAM Role"
          selected={isRole}
          disabled={disabled}
          onClick={() => onMethodChange(AWS_QUICK_ACCESS_METHOD.ROLE)}
        >
          <Badge variant="success" size="sm">
            Recommended
          </Badge>
        </RadioCard>
        <RadioCard
          icon={KeyRound}
          title="Static access keys"
          selected={!isRole}
          disabled={disabled}
          onClick={() => onMethodChange(AWS_QUICK_ACCESS_METHOD.STATIC)}
        />
      </div>
    </>
  );
}

function RoleConnectForm({
  externalId,
  templateLinks,
  method,
  onMethodChange,
  onBack,
  onSelectOrganizations,
  onConnected,
  onFooterChange,
}: ConnectFormProps) {
  const form = useForm<AwsQuickRoleValues>({
    resolver: zodResolver(awsQuickRoleSchema),
    mode: "onChange",
    defaultValues: { roleArn: "" },
  });
  const { connect, connectionError, isConnecting } = useAwsQuickConnect({
    externalId,
    onConnected,
    setFieldError: (field, message) => {
      if (field !== "roleArn") return false;
      form.setError(field, { type: "server", message });
      return true;
    },
  });
  const roleArn = form.watch("roleArn");
  const detectedAccountId = parseAwsAccountIdFromRoleArn(roleArn ?? "");

  useConnectFooter({
    isConnecting,
    isValid: form.formState.isValid,
    onBack,
    onFooterChange,
  });

  return (
    <Form {...form}>
      <form
        id={AWS_QUICK_CONNECT_FORM_ID}
        onSubmit={form.handleSubmit((values) =>
          connect({ method: AWS_QUICK_ACCESS_METHOD.ROLE, values }),
        )}
        className="flex flex-col gap-6"
      >
        <AccessMethodPicker
          method={method}
          onMethodChange={onMethodChange}
          onSelectOrganizations={onSelectOrganizations}
          disabled={isConnecting}
        />

        {isConnecting ? (
          <ConnectingNotice />
        ) : (
          <>
            <p className="text-text-neutral-primary text-sm leading-6">
              Paste the ARN of a read-only IAM role that trusts Prowler. Prowler
              reads the account id from the ARN.
            </p>

            {connectionError && (
              <ConnectionErrorAlert message={connectionError} />
            )}

            <WizardInputField
              control={form.control}
              name="roleArn"
              label="IAM Role ARN"
              labelPlacement="outside"
              placeholder="arn:aws:iam::123456789012:role/ProwlerScan"
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

            <CreateRoleHelp
              externalId={externalId}
              templateLinks={templateLinks}
            />
          </>
        )}
      </form>
    </Form>
  );
}

function CreateRoleHelp({
  externalId,
  templateLinks,
}: Pick<AwsQuickConnectStepProps, "externalId" | "templateLinks">) {
  return (
    <Collapsible className="flex flex-col gap-4">
      <CollapsibleTrigger asChild>
        <Button
          type="button"
          variant="link"
          size="link-sm"
          className="group h-auto w-fit gap-1 p-0"
        >
          Don&apos;t have a role yet? Create it with CloudFormation
          <ChevronDownIcon className="size-4 transition-transform group-data-[state=open]:rotate-180" />
        </Button>
      </CollapsibleTrigger>
      <CollapsibleContent className="flex flex-col gap-6">
        <div className="flex flex-col gap-2">
          <p className="text-text-neutral-primary text-sm leading-7 font-normal">
            1) Log in to the AWS account you want to scan.
          </p>
          <p className="text-text-neutral-primary text-sm leading-7 font-normal">
            2) Click <strong>Create IAM Role &amp; Policy</strong>.
            CloudFormation opens with the template and External ID already
            filled in. Acknowledge the IAM resources and click{" "}
            <strong>Create stack</strong>.
          </p>
          <p className="text-text-neutral-primary text-sm leading-7 font-normal">
            3) When the stack is <strong>CREATE_COMPLETE</strong>, copy{" "}
            <strong>ProwlerScanRoleArn</strong> from its{" "}
            <strong>Outputs</strong> tab and paste it above.
          </p>
          <p className="text-text-neutral-tertiary text-xs leading-5">
            The stack creates a read-only <strong>ProwlerScan</strong> role
            (SecurityAudit + ViewOnlyAccess) that only Prowler can assume.
          </p>
        </div>

        {externalId ? (
          <Button variant="outline" size="lg" className="w-fit" asChild>
            <a
              href={templateLinks.cloudformationQuickLink}
              target="_blank"
              rel="noopener noreferrer"
            >
              <ExternalLink className="size-5" />
              <span>Create IAM Role &amp; Policy</span>
            </a>
          </Button>
        ) : (
          <Button
            type="button"
            variant="outline"
            size="lg"
            className="w-fit"
            disabled
          >
            <ExternalLink className="size-5" />
            <span>Create IAM Role &amp; Policy</span>
          </Button>
        )}

        <div className="flex items-center gap-2">
          <span className="text-text-neutral-tertiary text-xs font-medium">
            External ID:
          </span>
          <CodeSnippet value={externalId} icon={<IdIcon size={16} />} />
        </div>

        <p className="text-text-neutral-tertiary text-xs leading-5">
          Want to review the permissions first, or deploy it yourself? See the{" "}
          <Button variant="link" size="link-sm" className="h-auto p-0" asChild>
            <a
              href={templateLinks.cloudformation}
              target="_blank"
              rel="noopener noreferrer"
            >
              CloudFormation template
            </a>
          </Button>{" "}
          or the{" "}
          <Button variant="link" size="link-sm" className="h-auto p-0" asChild>
            <a
              href={templateLinks.terraform}
              target="_blank"
              rel="noopener noreferrer"
            >
              Terraform code
            </a>
          </Button>
          .
        </p>
      </CollapsibleContent>
    </Collapsible>
  );
}

function StaticConnectForm({
  externalId,
  method,
  onMethodChange,
  onBack,
  onSelectOrganizations,
  onConnected,
  onFooterChange,
}: ConnectFormProps) {
  const form = useForm<AwsQuickStaticValues>({
    resolver: zodResolver(awsQuickStaticSchema),
    mode: "onChange",
    defaultValues: {
      accountId: "",
      awsAccessKeyId: "",
      awsSecretAccessKey: "",
      awsSessionToken: "",
    },
  });
  const { connect, connectionError, isConnecting } = useAwsQuickConnect({
    externalId,
    onConnected,
    setFieldError: (field: AwsQuickConnectField, message) => {
      if (field === "roleArn") return false;
      form.setError(field, { type: "server", message });
      return true;
    },
  });

  useConnectFooter({
    isConnecting,
    isValid: form.formState.isValid,
    onBack,
    onFooterChange,
  });

  return (
    <Form {...form}>
      <form
        id={AWS_QUICK_CONNECT_FORM_ID}
        onSubmit={form.handleSubmit((values) =>
          connect({ method: AWS_QUICK_ACCESS_METHOD.STATIC, values }),
        )}
        className="flex flex-col gap-6"
      >
        <AccessMethodPicker
          method={method}
          onMethodChange={onMethodChange}
          onSelectOrganizations={onSelectOrganizations}
          disabled={isConnecting}
        />

        {isConnecting ? (
          <ConnectingNotice />
        ) : (
          <>
            <p className="text-text-neutral-primary text-sm leading-6">
              Paste the access keys of an IAM user with the{" "}
              <strong>SecurityAudit</strong> and <strong>ViewOnlyAccess</strong>{" "}
              managed policies. Keys are stored encrypted.
            </p>

            {connectionError && (
              <ConnectionErrorAlert message={connectionError} />
            )}

            <WizardInputField
              control={form.control}
              name="accountId"
              label="AWS Account ID"
              labelPlacement="outside"
              placeholder="123456789012"
              isRequired
              normalizeValue={(value) => value.replace(/\D/g, "").slice(0, 12)}
            />
            <WizardInputField
              control={form.control}
              name="awsAccessKeyId"
              type="password"
              label="AWS Access Key ID"
              labelPlacement="outside"
              placeholder="AKIA..."
              isRequired
            />
            <WizardInputField
              control={form.control}
              name="awsSecretAccessKey"
              type="password"
              label="AWS Secret Access Key"
              labelPlacement="outside"
              placeholder="Enter the secret access key"
              isRequired
            />
            <WizardInputField
              control={form.control}
              name="awsSessionToken"
              type="password"
              label="AWS Session Token (optional)"
              labelPlacement="outside"
              placeholder="Only for temporary credentials"
              isRequired={false}
            />
          </>
        )}
      </form>
    </Form>
  );
}
