"use client";

import { Ban, Box, Boxes } from "lucide-react";

import { RadioCard } from "@/components/providers/radio-card";

interface AwsMethodSelectorProps {
  onSelectSingle: () => void;
  onSelectOrganizations: () => void;
}

export function AwsMethodSelector({
  onSelectSingle,
  onSelectOrganizations,
}: AwsMethodSelectorProps) {
  const isCloudEnv = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";

  return (
    <div className="flex flex-col gap-3">
      <p className="text-muted-foreground text-sm">
        Select a method to add your accounts to Prowler.
      </p>

      <RadioCard
        icon={Box}
        title="Add A Single AWS Cloud Account"
        onClick={onSelectSingle}
      />

      <RadioCard
        icon={isCloudEnv ? Boxes : Ban}
        title="Add Multiple Accounts With AWS Organizations"
        onClick={onSelectOrganizations}
        disabled={!isCloudEnv}
      >
        {!isCloudEnv && <CtaBadge />}
      </RadioCard>
    </div>
  );
}

function CtaBadge() {
  return (
    <a
      href="https://prowler.com/pricing"
      target="_blank"
      rel="noopener noreferrer"
      className="flex h-[52px] shrink-0 items-center justify-center rounded-lg px-4 py-3 transition-opacity hover:opacity-90"
      style={{
        backgroundImage:
          "linear-gradient(112deg, rgb(46, 229, 155) 3.5%, rgb(98, 223, 240) 98.8%)",
      }}
    >
      <div className="flex items-center gap-1.5">
        <span className="text-primary-foreground text-sm leading-6 font-bold">
          Available in Prowler Cloud
        </span>
      </div>
    </a>
  );
}
