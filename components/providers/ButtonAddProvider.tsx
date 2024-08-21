"use client";

import { Button, CircularProgress } from "@nextui-org/react";
import React from "react";
import { useFormStatus } from "react-dom";

export const ButtonAddProvider = () => {
  const { pending } = useFormStatus();
  return (
    <Button type="submit" area-disabled={pending}>
      {pending ? <CircularProgress aria-label="Loading..." /> : "Add provider"}
    </Button>
  );
};
