"use client";

import { useTransition } from "react";

import { useToast } from "@/components/ui";

type MuteRuleActionResult = {
  success?: string;
  errors?: {
    general?: string;
  };
} | null;

interface RunMuteRuleActionOptions<T extends MuteRuleActionResult> {
  setState?: (result: T) => void;
  onSuccess?: () => void;
  onError?: (message: string) => void;
  successTitle?: string;
  errorTitle?: string;
  successMessage?: string;
}

export function useMuteRuleAction() {
  const { toast } = useToast();
  const [isPending, startTransition] = useTransition();

  const runAction = <T extends MuteRuleActionResult>(
    execute: () => Promise<T>,
    options: RunMuteRuleActionOptions<T> = {},
  ) => {
    startTransition(() => {
      void (async () => {
        const result = await execute();

        options.setState?.(result);

        if (!result) {
          return;
        }

        if (result.success) {
          toast({
            title: options.successTitle ?? "Success",
            description: options.successMessage ?? result.success,
          });
          options.onSuccess?.();
          return;
        }

        const errorMessage = result.errors?.general;
        if (errorMessage) {
          toast({
            variant: "destructive",
            title: options.errorTitle ?? "Error",
            description: errorMessage,
          });
          options.onError?.(errorMessage);
        }
      })();
    });
  };

  return {
    isPending,
    runAction,
  };
}
