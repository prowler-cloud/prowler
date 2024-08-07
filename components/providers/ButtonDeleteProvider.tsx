"use client";

import { Button } from "@nextui-org/react";
import React from "react";
import { useFormStatus } from "react-dom";

import { DeleteIcon } from "../icons";

export const ButtonDeleteProvider = () => {
  const { pending } = useFormStatus();
  return (
    <Button
      variant="light"
      spinner={pending ? "Removing..." : "Remove"}
      type="submit"
      area-disabled={pending}
    >
      <DeleteIcon size={20} /> Delete
    </Button>
  );
};
