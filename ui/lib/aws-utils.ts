/**
 * Builds an AWS Console URL for a given resource ARN
 * Uses AWS Console's go/view service which accepts ARNs directly
 *
 * @param resourceArn - The AWS resource ARN
 * @returns Complete URL to view the resource in AWS Console, or null if ARN is invalid
 */
export function buildAwsConsoleUrl(resourceArn: string): string | null {
  if (!resourceArn || !resourceArn.startsWith("arn:")) {
    return null;
  }

  try {
    // AWS Console provides a universal URL that works with any ARN
    // Format: https://console.aws.amazon.com/go/view?arn=<ARN>
    const encodedArn = encodeURIComponent(resourceArn);
    return `https://console.aws.amazon.com/go/view?arn=${encodedArn}`;
  } catch (error) {
    console.error("Error building AWS Console URL:", error);
    return null;
  }
}

/**
 * Extracts the AWS region from an ARN
 * ARN format: arn:partition:service:region:account-id:resource
 *
 * @param resourceArn - The AWS resource ARN
 * @returns AWS region code or null if not found
 */
export function extractAwsRegionFromArn(resourceArn: string): string | null {
  if (!resourceArn || !resourceArn.startsWith("arn:")) {
    return null;
  }

  try {
    const parts = resourceArn.split(":");
    if (parts.length >= 4) {
      const region = parts[3];
      return region || null;
    }
    return null;
  } catch (error) {
    console.error("Error extracting region from ARN:", error);
    return null;
  }
}

/**
 * Extracts the AWS service from an ARN
 * ARN format: arn:partition:service:region:account-id:resource
 *
 * @param resourceArn - The AWS resource ARN
 * @returns AWS service name or null if not found
 */
export function extractAwsServiceFromArn(resourceArn: string): string | null {
  if (!resourceArn || !resourceArn.startsWith("arn:")) {
    return null;
  }

  try {
    const parts = resourceArn.split(":");
    if (parts.length >= 3) {
      const service = parts[2];
      return service || null;
    }
    return null;
  } catch (error) {
    console.error("Error extracting service from ARN:", error);
    return null;
  }
}
