"use client";

import { useState } from "react";

import { ProviderWizardModal } from "@/components/providers/wizard";
import { Button } from "@/components/shadcn";

import { AddIcon } from "../icons";

export const AddProviderButton = () => {
  const [open, setOpen] = useState(false);

  return (
    <>
      <Button onClick={() => setOpen(true)}>
        Add Cloud Provider
        <AddIcon size={20} />
      </Button>
      <ProviderWizardModal open={open} onOpenChange={setOpen} />
    </>
  );
};
