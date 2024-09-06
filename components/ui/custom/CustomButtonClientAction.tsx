"use client";

import { Button, CircularProgress } from "@nextui-org/react";
import clsx from "clsx";
import { useFormStatus } from "react-dom";

interface CustomButtonClientActionProps {
  buttonLabel: string;
  danger?: boolean;
}

export const CustomButtonClientAction = ({
  buttonLabel,
  danger = false,
}: CustomButtonClientActionProps) => {
  const { pending } = useFormStatus();

  return (
    <Button
      className={clsx("bg-transparent border-none p-0 m-0 h-fit min-w-min", {
        "text-danger": danger,
      })}
      spinner={<CircularProgress aria-label="Loading..." size="sm" />}
      type="submit"
      area-disabled={pending}
    >
      {buttonLabel}
    </Button>
  );
};
