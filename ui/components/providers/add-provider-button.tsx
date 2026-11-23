"use client";

import { useState } from "react";

import { ProviderWizardModal } from "@/components/providers/wizard";
import { Button } from "@/components/shadcn";

interface AddProviderButtonProps {
  onOpenWizard?: () => void;
}

export const AddProviderButton = ({ onOpenWizard }: AddProviderButtonProps) => {
  const [open, setOpen] = useState(false);

  const handleOpen = () => {
    if (onOpenWizard) {
      onOpenWizard();
      return;
    }

    setOpen(true);
  };

  return (
    <>
      <Button onClick={handleOpen}>Add Provider</Button>
      {!onOpenWizard && (
        <ProviderWizardModal open={open} onOpenChange={setOpen} />
      )}
    </>
  );
};
