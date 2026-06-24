// Uses the AWS Console's universal `/go/view` redirect so we don't have to
// special-case each service — the console resolves the ARN to the right page.
export const buildAwsConsoleUrl = (resourceArn: string): string | null => {
  if (!resourceArn || !resourceArn.startsWith("arn:")) {
    return null;
  }

  return `https://console.aws.amazon.com/go/view?arn=${encodeURIComponent(resourceArn)}`;
};
