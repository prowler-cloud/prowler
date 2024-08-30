"use client";

import { Button } from "@nextui-org/react";
import React from "react";
import { useFormStatus } from "react-dom";

export const ButtonEditUser = () => {
  const { pending } = useFormStatus();
  return (
    <Button type="submit" area-disabled={pending}>
      {pending ? "Saving..." : "Edit user"}
    </Button>
  );
};
