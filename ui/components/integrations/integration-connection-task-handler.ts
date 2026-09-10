"use client";

import { revalidateIntegrationConnectionPages } from "@/actions/integrations";
import { toast } from "@/components/shadcn/toast";
import { evaluateIntegrationConnectionTask } from "@/lib/integrations/test-connection-result";
import type { TaskKindHandler } from "@/store/task-watcher/store";
import type { IntegrationConnectionTaskResult } from "@/types/integrations";

const refreshIntegrationPages = (): void => {
  void revalidateIntegrationConnectionPages().catch(() => undefined);
};

export const integrationConnectionTaskHandler: TaskKindHandler = {
  onReady: (task) => {
    refreshIntegrationPages();
    const result = evaluateIntegrationConnectionTask(
      task.result as IntegrationConnectionTaskResult | undefined,
    );

    if (result.success) {
      toast({
        title: "Connection test successful!",
        description: result.message,
      });
      return;
    }

    toast({
      variant: "destructive",
      title: "Connection test failed",
      description: result.error,
    });
  },
  onError: (task) => {
    refreshIntegrationPages();
    toast({
      variant: "destructive",
      title: "Connection test failed",
      description: task.error || "The connection test failed unexpectedly.",
    });
  },
};
