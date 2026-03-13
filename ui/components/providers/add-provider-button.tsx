"use client";

import { useState } from "react";

import { ProviderWizardModal } from "@/components/providers/wizard";
import { Button } from "@/components/shadcn";

export const AddProviderButton = () => {
  const [open, setOpen] = useState(false);

  return (
    <>
      <Button onClick={() => setOpen(true)}>Add Provider</Button>
      <ProviderWizardModal open={open} onOpenChange={setOpen} />
    </>
  );
};
