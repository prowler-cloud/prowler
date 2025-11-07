import {
  baseUrlSchema,
  bedrockCredentialsSchema,
  openAICompatibleCredentialsSchema,
  openAICredentialsSchema,
} from "@/types/lighthouse/credentials";

/**
 * Validate credentials based on provider type
 */
export function validateCredentials(
  providerType: string,
  credentials: Record<string, any>,
): { success: boolean; error?: string } {
  try {
    switch (providerType) {
      case "openai":
        openAICredentialsSchema.parse(credentials);
        break;
      case "bedrock":
        bedrockCredentialsSchema.parse(credentials);
        break;
      case "openai_compatible":
        openAICompatibleCredentialsSchema.parse(credentials);
        break;
      default:
        return {
          success: false,
          error: `Unknown provider type: ${providerType}`,
        };
    }
    return { success: true };
  } catch (error: any) {
    const errorMessage =
      error?.issues?.[0]?.message || error?.message || "Validation failed";
    return {
      success: false,
      error: errorMessage,
    };
  }
}

/**
 * Validate base URL
 */
export function validateBaseUrl(baseUrl: string): {
  success: boolean;
  error?: string;
} {
  try {
    baseUrlSchema.parse(baseUrl);
    return { success: true };
  } catch (error: any) {
    const errorMessage =
      error?.issues?.[0]?.message || error?.message || "Invalid base URL";
    return {
      success: false,
      error: errorMessage,
    };
  }
}
