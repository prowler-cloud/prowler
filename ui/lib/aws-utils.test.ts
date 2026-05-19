import { describe, expect, it } from "vitest";

import { buildAwsConsoleUrl } from "./aws-utils";

describe("buildAwsConsoleUrl", () => {
  it("returns a `/go/view` URL with the ARN URL-encoded", () => {
    const arn = "arn:aws:s3:::my-bucket";
    expect(buildAwsConsoleUrl(arn)).toBe(
      `https://console.aws.amazon.com/go/view?arn=${encodeURIComponent(arn)}`,
    );
  });

  it("preserves regional and account scoping in the encoded ARN", () => {
    const arn =
      "arn:aws:iam::123456789012:role/MyRole-with+special/chars and spaces";
    const url = buildAwsConsoleUrl(arn);
    expect(url).not.toBeNull();
    expect(url).toContain(encodeURIComponent(arn));
  });

  it("returns null for missing or non-ARN inputs", () => {
    expect(buildAwsConsoleUrl("")).toBeNull();
    expect(buildAwsConsoleUrl("not-an-arn")).toBeNull();
    expect(buildAwsConsoleUrl("https://example.com")).toBeNull();
  });
});
