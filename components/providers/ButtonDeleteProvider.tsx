"use client";

import { Button } from "@nextui-org/react";
import React from "react";
import { useFormStatus } from "react-dom";

export const ButtonDeleteProvider = () => {
  const { pending } = useFormStatus();
  return (
    <Button
      className="bg-transparent border-none p-0 m-0 h-fit min-w-min text-danger"
      spinner={pending ? "Removing..." : "Remove"}
      type="submit"
      area-disabled={pending}
    >
      Delete
    </Button>
  );
};
