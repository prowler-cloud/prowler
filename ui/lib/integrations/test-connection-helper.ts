import { pollConnectionTestStatus, testIntegrationConnection } from "@/actions/integrations";

interface TestConnectionOptions {
  integrationId: string;
  integrationType: "s3" | "security_hub";
  onSuccess?: (message: string) => void;
  onError?: (message: string) => void;
  onStart?: () => void;
}

export const runTestConnection = async ({
  integrationId,
  integrationType,
  onSuccess,
  onError,
  onStart,
}: TestConnectionOptions) => {
  try {
    // Start the test without waiting for completion
    const result = await testIntegrationConnection(integrationId, false);
    
    if (!result || (!result.success && !result.error)) {
      onError?.("Connection test could not be started. Please try again.");
      return;
    }
    
    if (result.error) {
      onError?.(result.error);
      return;
    }
    
    if (!result.taskId) {
      onError?.("Failed to start connection test. No task ID received.");
      return;
    }
    
    // Notify that test has started
    onStart?.();
    
    // Poll for the test completion
    const pollResult = await pollConnectionTestStatus(result.taskId);
    
    if (pollResult.success) {
      const defaultMessage = integrationType === "s3" 
        ? "Successfully connected to S3 bucket."
        : "Successfully connected to AWS Security Hub.";
      onSuccess?.(pollResult.message || defaultMessage);
    } else {
      const defaultError = integrationType === "s3"
        ? "Failed to connect to S3 bucket."
        : "Failed to connect to AWS Security Hub.";
      onError?.(pollResult.error || defaultError);
    }
  } catch (error) {
    onError?.("Failed to start connection test. You can try manually using the Test Connection button.");
  }
};

export const triggerTestConnectionWithDelay = (
  integrationId: string | undefined,
  shouldTestConnection: boolean | undefined,
  integrationType: "s3" | "security_hub",
  toast: any,
  delay = 200,
) => {
  if (!integrationId || !shouldTestConnection) {
    return;
  }

  setTimeout(() => {
    runTestConnection({
      integrationId,
      integrationType,
      onStart: () => {
        const description = integrationType === "s3"
          ? "Testing connection to S3 bucket..."
          : "Testing connection to AWS Security Hub...";
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
    });
  }, delay);
};