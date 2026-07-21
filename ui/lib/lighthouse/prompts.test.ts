import { describe, expect, it } from "vitest";

import { buildFindingAnalysisPrompt } from "./prompts";

describe("buildFindingAnalysisPrompt", () => {
  it("should include the complete finding context", () => {
    // Given / When
    const prompt = buildFindingAnalysisPrompt({
      findingId: "finding-1",
      providerUid: "provider-1",
      resourceUid: "resource-1",
      checkId: "check-1",
      severity: "critical",
      status: "FAIL",
      detail: "The resource is publicly accessible.",
      risk: "Unauthorized access can expose sensitive data.",
    });

    // Then
    expect(prompt).toBe(
      `Get all the possible information from Prowler Application and from Prowler Hub to have the full context.

Analyze this security finding and provide remediation guidance:

- **Finding ID**: finding-1
- **Provider UID**: provider-1
- **Resource UID**: resource-1
- **Check ID**: check-1
- **Severity**: critical
- **Status**: FAIL
- **Detail**: The resource is publicly accessible.
- **Risk**: Unauthorized access can expose sensitive data.`,
    );
  });
});
