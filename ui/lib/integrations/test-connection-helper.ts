import {
  revalidateIntegrationConnectionPages,
  testIntegrationConnection,
} from "@/actions/integrations";
import type { useToast } from "@/components/shadcn/toast/use-toast";
import { evaluateIntegrationConnectionTask } from "@/lib/integrations/test-connection-result";
import {
  TASK_WATCHER_STATUS,
  trackAndPollTask,
} from "@/store/task-watcher/store";
import {
  INTEGRATION_CONNECTION_TASK_KIND,
  type IntegrationConnectionTaskResult,
  type IntegrationConnectionTestResponse,
} from "@/types/integrations";

// Integration configuration type
export interface IntegrationMessages {
  testingMessage: string;
  successMessage: string;
  errorMessage: string;
}

// Configuration map for integration-specific messages
const INTEGRATION_CONFIG: Record<string, IntegrationMessages> = {
  "amazon-s3": {
    testingMessage: "Testing connection to Amazon S3 bucket...",
    successMessage: "Successfully connected to Amazon S3 bucket.",
    errorMessage: "Failed to connect to Amazon S3 bucket.",
  },
  "aws-security-hub": {
    testingMessage: "Testing connection to AWS Security Hub...",
    successMessage: "Successfully connected to AWS Security Hub.",
    errorMessage: "Failed to connect to AWS Security Hub.",
  },
  // Legacy mappings for backward compatibility
  s3: {
    testingMessage: "Testing connection to Amazon S3 bucket...",
    successMessage: "Successfully connected to Amazon S3 bucket.",
    errorMessage: "Failed to connect to Amazon S3 bucket.",
  },
  security_hub: {
    testingMessage: "Testing connection to AWS Security Hub...",
    successMessage: "Successfully connected to AWS Security Hub.",
    errorMessage: "Failed to connect to AWS Security Hub.",
  },
  // Add new integrations here as needed
};

// Helper function to register new integration types
export const registerIntegrationType = (
  type: string,
  messages: IntegrationMessages,
): void => {
  INTEGRATION_CONFIG[type] = messages;
};

// Helper function to get supported integration types
export const getSupportedIntegrationTypes = (): string[] => {
  return Object.keys(INTEGRATION_CONFIG);
};

interface TestConnectionOptions {
  integrationId: string;
  integrationType: string;
  onSuccess?: (message: string) => void;
  onError?: (message: string) => void;
  onStart?: () => void;
  onComplete?: () => void;
}

export const executeIntegrationConnectionTest = async (
  integrationId: string,
  onStarted?: () => void,
): Promise<IntegrationConnectionTestResponse> => {
  const started = await testIntegrationConnection(integrationId);

  if (!started.success) {
    return {
      success: false,
      error: started.error || "Connection test could not be started.",
    };
  }

  if (!started.taskId) {
    return {
      success: false,
      error: "Failed to start connection test. No task ID received.",
    };
  }

  onStarted?.();

  const tracked = await trackAndPollTask<IntegrationConnectionTaskResult>({
    taskId: started.taskId,
    kind: INTEGRATION_CONNECTION_TASK_KIND,
    meta: { integrationId },
    notifyHandler: false,
  });

  await revalidateIntegrationConnectionPages();

  if (tracked.status !== TASK_WATCHER_STATUS.READY) {
    return {
      success: false,
      error: tracked.error || "Failed to track the connection test.",
    };
  }

  return evaluateIntegrationConnectionTask(tracked.result);
};

export const runTestConnection = async ({
  integrationId,
  integrationType,
  onSuccess,
  onError,
  onStart,
  onComplete,
}: TestConnectionOptions) => {
  try {
    const result = await executeIntegrationConnectionTest(
      integrationId,
      onStart,
    );

    if (result.success) {
      const config = INTEGRATION_CONFIG[integrationType];
      const defaultMessage =
        config?.successMessage ||
        `Successfully connected to ${integrationType}.`;
      onSuccess?.(result.message || defaultMessage);
    } else {
      const config = INTEGRATION_CONFIG[integrationType];
      const defaultError =
        config?.errorMessage || `Failed to connect to ${integrationType}.`;
      onError?.(result.error || defaultError);
    }
  } catch (_error) {
    onError?.(
      "Failed to start connection test. You can try manually using the Test Connection button.",
    );
  } finally {
    onComplete?.();
  }
};

export const triggerTestConnectionWithDelay = (
  integrationId: string | undefined,
  shouldTestConnection: boolean | undefined,
  integrationType: string,
  toast: ReturnType<typeof useToast>["toast"],
  delay = 200,
  onComplete?: () => void,
) => {
  if (!integrationId || !shouldTestConnection) {
    onComplete?.();
    return;
  }

  setTimeout(() => {
    runTestConnection({
      integrationId,
      integrationType,
      onStart: () => {
        const config = INTEGRATION_CONFIG[integrationType];
        const description =
          config?.testingMessage ||
          `Testing connection to ${integrationType}...`;
        toast({
          title: "Connection test started!",
          description,
        });
      },
      onSuccess: (message) => {
        toast({
          title: "Connection test successful!",
          description: message,
        });
      },
      onError: (message) => {
        toast({
          variant: "destructive",
          title: "Connection test failed",
          description: message,
        });
      },
      onComplete,
    });
  }, delay);
};
