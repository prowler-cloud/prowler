import { Dispatch, SetStateAction } from "react";

import { getMutedFindingsConfig } from "@/actions/processors";

import { MutedFindingsConfigForm } from "./muted-findings-config-form";

interface SSRMutedFindingsConfigFormWrapperProps {
  setIsOpen: Dispatch<SetStateAction<boolean>>;
  onConfigDeleted: () => void | Promise<void>;
}

export async function SSRMutedFindingsConfigFormWrapper({
  setIsOpen,
  onConfigDeleted,
}: SSRMutedFindingsConfigFormWrapperProps) {
  const config = await getMutedFindingsConfig();

  return (
    <MutedFindingsConfigForm
      setIsOpen={setIsOpen}
      existingConfig={config?.data}
      onConfigDeleted={onConfigDeleted}
    />
  );
}
