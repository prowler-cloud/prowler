"use client";

import { CloudAlert } from "lucide-react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/shadcn";

/**
 * Warning card shown when AWS is not connected
 * Provides button to navigate to Providers page
 */
export const AWSConnectionWarning = () => {
  const router = useRouter();

  const handleNavigateToProviders = () => {
    router.push("/providers");
  };

  return (
    <div className="rounded-lg border border-yellow-600/30 bg-yellow-50 p-6 dark:bg-yellow-950/20">
      <div className="flex items-start gap-4">
        <CloudAlert
          className="mt-1 flex-shrink-0 text-yellow-600 dark:text-yellow-400"
          size={24}
        />
        <div className="flex-1">
          <h3 className="mb-2 font-semibold text-yellow-900 dark:text-yellow-100">
            AWS Connection Required
          </h3>
          <p className="mb-4 text-sm text-yellow-800 dark:text-yellow-200">
            Attack Path analysis requires at least one connected AWS provider.
            Please connect your AWS account first.
          </p>
          <Button
            variant="outline"
            size="sm"
            onClick={handleNavigateToProviders}
            className="font-medium"
          >
            Connect AWS Provider
          </Button>
        </div>
      </div>
    </div>
  );
};
