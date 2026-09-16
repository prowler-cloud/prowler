import type {
  IntegrationConnectionTaskResult,
  IntegrationConnectionTestResponse,
} from "@/types/integrations";

export const evaluateIntegrationConnectionTask = (
  result: IntegrationConnectionTaskResult | undefined,
): IntegrationConnectionTestResponse => {
  const isSuccessful = result?.connected === true && result.error === null;

  if (isSuccessful) {
    return {
      success: true,
      message: "Connection test completed successfully.",
    };
  }

  return {
    success: false,
    error: result?.error || "Connection test failed.",
    failedChannelId: result?.channel ?? null,
  };
};
