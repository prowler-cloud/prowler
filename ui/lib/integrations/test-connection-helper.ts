import {
  pollConnectionTestStatus,
  testIntegrationConnection,
} from "@/actions/integrations";

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

export const runTestConnection = async ({
  integrationId,
  integrationType,
  onSuccess,
  onError,
  onStart,
  onComplete,
}: TestConnectionOptions) => {
  try {
    // Start the test without waiting for completion
    const result = await testIntegrationConnection(integrationId, false);

    if (!result || (!result.success && !result.error)) {
      onError?.("Connection test could not be started. Please try again.");
      onComplete?.();
      return;
    }

    if (result.error) {
      onError?.(result.error);
      onComplete?.();
      return;
    }

    if (!result.taskId) {
      onError?.("Failed to start connection test. No task ID received.");
      onComplete?.();
      return;
    }

    // Notify that test has started
    onStart?.();

    // Poll for the test completion
    const pollResult = await pollConnectionTestStatus(result.taskId);

    if (pollResult.success) {
      const config = INTEGRATION_CONFIG[integrationType];
      const defaultMessage =
        config?.successMessage ||
        `Successfully connected to ${integrationType}.`;
      onSuccess?.(pollResult.message || defaultMessage);
    } else {
      const config = INTEGRATION_CONFIG[integrationType];
      const defaultError =
        config?.errorMessage || `Failed to connect to ${integrationType}.`;
      onError?.(pollResult.error || defaultError);
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
  toast: any,
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
