import { describe, expect } from "vitest";

import { it } from "@/__tests__/fixtures";
import {
  INGESTION_REJECTION,
  ingestionFixture,
  ingestionRejectionFixture,
  partiallyProcessedIngestionFixture,
} from "@/__tests__/msw/handlers/ingestions.fixtures";

import { ScansPageHarness } from "./scans-page.harness";

describe("Scans page import findings", () => {
  it("imports one valid finding file without scan permission or providers", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount();

    expect(harness.hasImportFindingsAction()).toBe(true);
    await harness.openImportFindings();
    await harness.selectFile(
      new File(['[{"type":"finding"}]'], "findings.ocsf.json", {
        type: "application/json",
      }),
    );
    await harness.submitImport();

    await harness.waitForCompletedSummary();
    // The summary is on screen, so the toast would have been raised in the same
    // render: its absence is the open dialog suppressing it.
    expect(harness.hasCompletionNotification()).toBe(false);
    expect(harness.pageRefreshCount).toBe(1);
    expect(harness.ingestionPostCount).toBe(1);
    expect(await harness.uploadedFileName()).toBe("findings.ocsf.json");
    expect(harness.ingestionStatusPollCount).toBeGreaterThanOrEqual(2);
  });

  it("hides Import Findings in Local Server", async ({ seedRuntimeConfig }) => {
    seedRuntimeConfig({ cloudEnabled: false });
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount();

    expect(harness.hasImportFindingsAction()).toBe(false);
  });

  it("hides Import Findings without Manage Ingestions", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount({ hasManageIngestionsPermission: false });

    expect(harness.hasImportFindingsAction()).toBe(false);
  });

  it("supports keyboard activation and drag-and-drop selection", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount();
    await harness.openImportFindings();

    await expect(harness.activateDropzoneWithKeyboard()).resolves.toBe(true);
    await harness.dropFile(
      new File(["[]"], "dropped.OCSF.JSON", { type: "application/json" }),
    );

    expect(harness.selectedFileName()).toBe("dropped.OCSF.JSON");
    expect(harness.isImportEnabled()).toBe(true);
  });

  it("replaces a selected file and rejects unsupported and empty selections", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount();
    await harness.openImportFindings();
    await harness.selectFile(new File(["[]"], "first.ocsf.json"));
    await harness.selectFile(new File(["[]"], "replacement.ocsf.json"));

    expect(harness.selectedFileName()).toBe("replacement.ocsf.json");
    await harness.selectFile(new File(["[]"], "unsupported.json"));
    await harness.waitForValidationMessage(/\.ocsf\.json/i);
    expect(harness.ingestionPostCount).toBe(0);

    await harness.selectFile(new File([], "empty.ocsf.json"));
    await harness.waitForValidationMessage(/empty/i);
    expect(harness.ingestionPostCount).toBe(0);
  });

  it("clears an unsubmitted selection after closing the dialog", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount();
    await harness.openImportFindings();
    await harness.selectFile(new File(["[]"], "findings.ocsf.json"));
    await harness.closeImportFindings();
    await harness.openImportFindings();

    expect(harness.selectedFileName()).toBeNull();
    expect(harness.isImportEnabled()).toBe(false);
  });

  for (const rejection of Object.values(INGESTION_REJECTION)) {
    it(`keeps the file recoverable after a ${rejection} upload rejection`, async () => {
      const rejectionFixture = ingestionRejectionFixture(rejection);
      const harness = new ScansPageHarness(ingestionFixture());
      await harness.mount({ uploadRejection: rejectionFixture });
      await harness.openImportFindings();
      await harness.selectFile(new File(["[]"], "findings.ocsf.json"));
      await harness.submitImport();

      await harness.waitForUploadError(
        new RegExp(rejectionFixture.message, "i"),
      );
      expect(harness.selectedFileName()).toBe("findings.ocsf.json");
      expect(harness.ingestionPostCount).toBe(1);

      await harness.retryUpload();
      expect(harness.ingestionPostCount).toBe(2);
    });
  }

  it("continues tracking an accepted import while the dialog is closed", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount({ statusSequence: ["processing", "completed"] });
    await harness.openImportFindings();
    await harness.selectFile(new File(["[]"], "findings.ocsf.json"));
    await harness.submitImport();
    await harness.waitForTrackingStatus();
    await harness.closeImportFindings();

    await harness.openImportFindings();
    await harness.waitForCompletedSummary();
    expect(harness.ingestionPostCount).toBe(1);
  });

  it("keeps an in-flight submission after closing and reopening the dialog", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount({
      uploadDelayMs: 3000,
      statusSequence: ["processing", "completed"],
    });
    await harness.openImportFindings();
    await harness.selectFile(new File(["[]"], "findings.ocsf.json"));
    await harness.submitImport();
    await harness.waitForUploadInProgress();
    await harness.closeImportFindings();
    await harness.openImportFindings();

    expect(harness.isUploadInProgress()).toBe(true);
    expect(harness.selectedFileName()).toBe("findings.ocsf.json");

    await harness.waitForTrackingStatus();
    expect(harness.ingestionPostCount).toBe(1);
  });

  it("refuses to swap the file while an import is in flight", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount({
      uploadDelayMs: 3000,
      statusSequence: ["processing", "completed"],
    });
    await harness.openImportFindings();
    await harness.selectFile(new File(["[]"], "findings.ocsf.json"));
    await harness.submitImport();
    await harness.waitForUploadInProgress();

    expect(harness.isDropzoneFrozen()).toBe(true);
    await harness.attemptDrop(new File(["[]"], "swapped.ocsf.json"));
    await expect(harness.activateDropzoneWithKeyboard()).resolves.toBe(false);

    expect(harness.selectedFileName()).toBe("findings.ocsf.json");
    // A swap would reset to ready, re-enabling submission for a second POST.
    expect(harness.isUploadInProgress()).toBe(true);

    await harness.waitForTrackingStatus();
    expect(harness.ingestionPostCount).toBe(1);
  });

  it("notifies when an import completes while the dialog is closed", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount({ statusSequence: ["processing", "completed"] });
    await harness.openImportFindings();
    await harness.selectFile(new File(["[]"], "findings.ocsf.json"));
    await harness.submitImport();
    await harness.waitForTrackingStatus();
    await harness.closeImportFindings();

    await harness.waitForCompletionNotification();
    expect(harness.ingestionPostCount).toBe(1);
  });

  it("offers a fresh import when reopening after a background completion", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount({ statusSequence: ["processing", "completed"] });
    await harness.openImportFindings();
    await harness.selectFile(new File(["[]"], "findings.ocsf.json"));
    await harness.submitImport();
    await harness.waitForTrackingStatus();
    await harness.closeImportFindings();
    await harness.waitForCompletionNotification();

    await harness.openImportFindings();
    // Without the reopen reset the summary renders in place of the dropzone and
    // the submit, leaving no way to import a second report.
    expect(harness.hasCompletedSummary()).toBe(false);
    await harness.selectFile(new File(["[]"], "another.ocsf.json"));
    expect(harness.selectedFileName()).toBe("another.ocsf.json");
    expect(harness.isImportEnabled()).toBe(true);
    expect(harness.ingestionPostCount).toBe(1);
  });

  it("notifies when the dialog closes immediately before the import completes", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount({
      holdStatusResponse: true,
      statusSequence: ["completed"],
    });
    await harness.openImportFindings();
    await harness.selectFile(new File(["[]"], "findings.ocsf.json"));
    await harness.submitImport();
    await harness.waitForFirstStatusPoll();

    await harness.closeImmediatelyBeforeStatusCompletes();

    await harness.waitForCompletionNotification();
    expect(harness.pageRefreshCount).toBe(1);
    expect(harness.ingestionPostCount).toBe(1);
  });

  it("retries a failed terminal import with the selected file", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount({ statusSequence: ["failed"] });
    await harness.openImportFindings();
    await harness.selectFile(new File(["[]"], "findings.ocsf.json"));
    await harness.submitImport();
    await harness.waitForFailedImport();
    expect(harness.pageRefreshCount).toBe(0);

    await harness.retryUpload();
    expect(harness.ingestionPostCount).toBe(2);
  });

  it("reports how many records a failed import processed", async () => {
    const harness = new ScansPageHarness(partiallyProcessedIngestionFixture());
    await harness.mount({ statusSequence: ["failed"] });
    await harness.openImportFindings();
    await harness.selectFile(new File(["[]"], "findings.ocsf.json"));
    await harness.submitImport();

    await harness.waitForFailedImport();
    await harness.waitForFailedImportSummary();
    expect(harness.ingestionPostCount).toBe(1);
  });

  it("clears a terminal result after closing the dialog", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount({ statusSequence: ["failed"] });
    await harness.openImportFindings();
    await harness.selectFile(new File(["[]"], "findings.ocsf.json"));
    await harness.submitImport();
    await harness.waitForFailedImport();
    await harness.closeImportFindings();
    await harness.openImportFindings();

    expect(harness.selectedFileName()).toBeNull();
    expect(harness.isImportEnabled()).toBe(false);
  });

  it("retries a transient status failure without re-uploading", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount({
      statusErrorAt: 1,
      statusSequence: ["processing", "completed"],
    });
    await harness.openImportFindings();
    await harness.selectFile(new File(["[]"], "findings.ocsf.json"));
    await harness.submitImport();
    await harness.waitForStatusError();

    await harness.retryStatus();
    expect(harness.ingestionPostCount).toBe(1);
  });

  it("abandons a stuck import and starts over", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount({ statusErrorAt: 1 });
    await harness.openImportFindings();
    await harness.selectFile(new File(["[]"], "findings.ocsf.json"));
    await harness.submitImport();
    await harness.waitForStatusError();

    await harness.stopTracking();
    expect(harness.isDropzoneFrozen()).toBe(false);
    expect(harness.selectedFileName()).toBeNull();
    // The backend job survives the reset, so a second upload can duplicate it.
    expect(harness.hasDuplicateImportWarning()).toBe(true);

    await harness.selectFile(new File(["[]"], "another.ocsf.json"));
    expect(harness.selectedFileName()).toBe("another.ocsf.json");
    expect(harness.isImportEnabled()).toBe(true);
    expect(harness.ingestionPostCount).toBe(1);
  });

  it("never overlaps status polls for an accepted import", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    // The delay has to outlast POLL_INTERVAL_MS: an interval-driven poll fires
    // its second request while this first one is still in flight.
    await harness.mount({
      statusDelayMs: 7500,
      statusSequence: ["completed"],
    });
    await harness.openImportFindings();
    await harness.selectFile(new File(["[]"], "findings.ocsf.json"));
    await harness.submitImport();

    await harness.waitForCompletedSummary();
    expect(harness.maximumInFlightStatusRequests).toBe(1);
  });

  it("stops polling a tracked import after leaving the page", async () => {
    const harness = new ScansPageHarness(ingestionFixture());
    await harness.mount({ statusDelayMs: 500 });
    await harness.openImportFindings();
    await harness.selectFile(new File(["[]"], "findings.ocsf.json"));
    await harness.submitImport();
    await harness.waitForFirstStatusPoll();
    await harness.leaveScansPage();
    const pollsWhenLeaving = harness.ingestionStatusPollCount;

    // An unaborted poll answers into the dead page and chains the next one,
    // refreshing and toasting over whatever route the user moved to.
    await harness.waitPastTheNextPoll();
    expect(harness.ingestionStatusPollCount).toBe(pollsWhenLeaving);
  });
});
