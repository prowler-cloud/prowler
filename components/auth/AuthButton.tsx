"use client";

import { Button, CircularProgress } from "@nextui-org/react";
import React from "react";
import { useFormStatus } from "react-dom";

export const AuthButton = ({ type }: { type: string }) => {
  const { pending } = useFormStatus();

  return (
    <Button color="primary" type="submit" aria-disabled={pending}>
      {pending ? (
        <CircularProgress aria-label="Loading..." size="sm" />
      ) : type === "sign-in" ? (
        "Log In"
      ) : (
        "Sign Up"
      )}
    </Button>
  );
};
