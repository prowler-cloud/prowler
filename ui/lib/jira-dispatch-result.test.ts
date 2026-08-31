import { describe, expect, it } from "vitest";

import type { JiraDispatchTaskResult } from "@/types/integrations";

import {
  buildJiraDispatchSkippedMessage,
  evaluateJiraDispatchTask,
  getJiraDispatchSkippedCount,
  getJiraDispatchSuccessCount,
} from "./jira-dispatch-result";

const skipped = (key: string, findingId = `finding-${key}`) => ({
  finding_id: findingId,
  issue_key: key,
  issue_url: `https://acme.atlassian.net/browse/${key}`,
  issue_status: "To Do",
});

describe("getJiraDispatchSkippedCount", () => {
  it("uses the larger of the count and the list", () => {
    expect(getJiraDispatchSkippedCount(undefined)).toBe(0);
    expect(getJiraDispatchSkippedCount({ skipped_count: 2 })).toBe(2);
    expect(
      getJiraDispatchSkippedCount({
        skipped_count: 1,
        skipped: [skipped("SEC-1"), skipped("SEC-2")],
      }),
    ).toBe(2);
  });
});

describe("buildJiraDispatchSkippedMessage", () => {
  it("is empty when nothing was skipped", () => {
    expect(buildJiraDispatchSkippedMessage({ created_count: 1 })).toBe("");
  });

  it("names the existing issues, capped", () => {
    expect(
      buildJiraDispatchSkippedMessage({
        skipped_count: 1,
        skipped: [skipped("SEC-1")],
      }),
    ).toBe("1 Finding already has an open Jira issue (SEC-1).");
    expect(
      buildJiraDispatchSkippedMessage({
        skipped_count: 5,
        skipped: [
          skipped("SEC-1"),
          skipped("SEC-2"),
          skipped("SEC-3"),
          skipped("SEC-4"),
          skipped("SEC-5"),
        ],
      }),
    ).toBe(
      "5 Findings already have an open Jira issue (SEC-1, SEC-2, SEC-3, +2 more).",
    );
  });

  it("works with a count but no keys (in-flight reservations)", () => {
    expect(
      buildJiraDispatchSkippedMessage({
        skipped_count: 1,
        skipped: [{ finding_id: "finding-1" }],
      }),
    ).toBe("1 Finding already has an open Jira issue.");
  });
});

describe("evaluateJiraDispatchTask with skipped findings", () => {
  it("treats an all-skipped dispatch as success", () => {
    // Given
    const result: JiraDispatchTaskResult = {
      created_count: 0,
      skipped_count: 2,
      failed_count: 0,
      skipped: [skipped("SEC-1"), skipped("SEC-2")],
    };

    // When
    const outcome = evaluateJiraDispatchTask("completed", result);

    // Then
    expect(outcome).toEqual({
      success: true,
      message: "2 Findings already have an open Jira issue (SEC-1, SEC-2).",
      skippedCount: 2,
    });
    expect(getJiraDispatchSuccessCount(result)).toBe(0);
  });

  it("appends the skipped summary to a success message", () => {
    // Given
    const result: JiraDispatchTaskResult = {
      created_count: 3,
      skipped_count: 1,
      failed_count: 0,
      skipped: [skipped("SEC-9")],
    };

    // When
    const outcome = evaluateJiraDispatchTask("completed", result);

    // Then
    expect(outcome).toEqual({
      success: true,
      message:
        "3 Jira issues were created or updated successfully. 1 Finding already has an open Jira issue (SEC-9).",
      skippedCount: 1,
    });
  });

  it("keeps a skipped-and-failed dispatch as a warning, not an error", () => {
    // Given
    const result: JiraDispatchTaskResult = {
      created_count: 0,
      skipped_count: 1,
      failed_count: 1,
      skipped: [skipped("SEC-1")],
      error: "Failed to create Jira issue.",
    };

    // When
    const outcome = evaluateJiraDispatchTask("completed", result);

    // Then
    expect(outcome.success).toBe(true);
    if (outcome.success) {
      expect(outcome.message).toBe(
        "1 Finding already has an open Jira issue (SEC-1).",
      );
      expect(outcome.warning).toContain("1 failed");
      expect(outcome.skippedCount).toBe(1);
    }
  });

  it("still fails when nothing was created nor skipped", () => {
    expect(
      evaluateJiraDispatchTask("completed", {
        created_count: 0,
        failed_count: 0,
      }),
    ).toEqual({
      success: false,
      error: "Jira dispatch completed but did not create or update any issues.",
    });
  });

  it("does not add skippedCount to plain successes", () => {
    expect(evaluateJiraDispatchTask("completed", { created_count: 1 })).toEqual(
      {
        success: true,
        message: "Finding successfully sent to Jira!",
      },
    );
  });
});
