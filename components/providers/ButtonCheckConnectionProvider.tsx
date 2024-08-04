"use client";

import { Button } from "@nextui-org/react";
import React from "react";
import { useFormStatus } from "react-dom";

import { CheckIcon } from "../icons";

export const ButtonCheckConnectionProvider = () => {
  const { pending } = useFormStatus();
  return (
    <Button
      variant="light"
      spinner={pending ? "Checking..." : " Check"}
      type="submit"
      area-disabled={pending}
    >
      <CheckIcon size={20} /> Check connection
    </Button>
  );
};
