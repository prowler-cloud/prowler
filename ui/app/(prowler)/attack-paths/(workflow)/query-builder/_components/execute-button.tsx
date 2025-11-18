"use client";

import { Play } from "lucide-react";

import { Button } from "@/components/shadcn";

interface ExecuteButtonProps {
  isLoading: boolean;
  isDisabled: boolean;
  onExecute: () => void;
}

/**
 * Execute query button component
 * Triggers query execution with loading state
 */
export const ExecuteButton = ({
  isLoading,
  isDisabled,
  onExecute,
}: ExecuteButtonProps) => {
  return (
    <Button
      variant="default"
      size="lg"
      disabled={isDisabled || isLoading}
      onClick={onExecute}
      className="w-full gap-2 font-semibold sm:w-auto"
    >
      {!isLoading && <Play size={18} />}
      {isLoading ? "Executing Query..." : "Execute Query"}
    </Button>
  );
};
