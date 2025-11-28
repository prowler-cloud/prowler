"use client";

import { RadioGroup } from "@heroui/radio";
import { useRouter, useSearchParams } from "next/navigation";

import { CustomRadio } from "@/components/ui/custom";

const BEDROCK_AUTH_METHODS = {
  API_KEY: "api_key",
  IAM: "iam",
} as const;

type BedrockAuthMethod =
  (typeof BEDROCK_AUTH_METHODS)[keyof typeof BEDROCK_AUTH_METHODS];

export const SelectBedrockAuthMethod = () => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const currentAuth = searchParams.get("auth") as BedrockAuthMethod | null;

  const handleSelectionChange = (value: string) => {
    const params = new URLSearchParams(searchParams.toString());
    params.set("auth", value);
    router.push(`?${params.toString()}`);
  };

  return (
    <div className="flex w-full flex-col gap-6">
      <div>
        <h2 className="mb-2 text-xl font-semibold">Connect Amazon Bedrock</h2>
        <p className="text-text-neutral-secondary text-sm">
          Choose how you want to authenticate with Amazon Bedrock. You can use a
          dedicated Bedrock API key or long-term AWS access keys.
        </p>
      </div>

      <div className="flex flex-col gap-3">
        <RadioGroup
          className="flex flex-col gap-3"
          value={currentAuth || ""}
          onValueChange={handleSelectionChange}
        >
          <CustomRadio value={BEDROCK_AUTH_METHODS.API_KEY}>
            <div className="flex items-center">
              <span className="ml-2">Use Bedrock API Key</span>
            </div>
          </CustomRadio>

          <CustomRadio value={BEDROCK_AUTH_METHODS.IAM}>
            <div className="flex items-center">
              <span className="ml-2">Use AWS Access Key & Secret</span>
            </div>
          </CustomRadio>
        </RadioGroup>
      </div>
    </div>
  );
};
