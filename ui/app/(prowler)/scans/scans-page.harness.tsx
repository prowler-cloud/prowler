// Aliased: `useRouter()` inside a class trips rules-of-hooks, and under the
// suite's mock it is a plain getter for the shared router singleton.
import { useRouter as readMockedRouter } from "next/navigation";
import { vi } from "vitest";

import { BrowserHarness } from "@/__tests__/browser-harness";
import { handlersForIngestion } from "@/__tests__/msw/handlers/ingestions";
import type {
  IngestionFixture,
  IngestionRejectionFixture,
} from "@/__tests__/msw/handlers/ingestions.fixtures";
import { worker } from "@/__tests__/msw/worker";
import { render } from "@/__tests__/render-browser";
import { ScansPageShell } from "@/components/scans/scans-page-shell";
import { ScanJobsTable } from "@/components/scans/table/scan-jobs-table";
import { SCAN_JOBS_TAB } from "@/types";

interface MountOptions {
  hasManageIngestionsPermission?: boolean;
  hasManageScansPermission?: boolean;
  uploadRejection?: IngestionRejectionFixture;
  uploadDelayMs?: number;
  statusErrorAt?: number;
  statusDelayMs?: number;
  statusSequence?: Array<"processing" | "completed" | "failed">;
}

export class ScansPageHarness extends BrowserHarness<IngestionFixture> {
  private maxInFlightStatusRequests = 0;
  private mounted: ReturnType<typeof render> | null = null;
  private statusDelayMs = 0;

  async mount({
    hasManageIngestionsPermission = true,
    hasManageScansPermission = false,
    uploadRejection,
    uploadDelayMs,
    statusErrorAt,
    statusDelayMs,
    statusSequence,
  }: MountOptions = {}): Promise<void> {
    worker.use(
      ...handlersForIngestion(this.fixture, {
        uploadRejection,
        uploadDelayMs,
        statusErrorAt,
        statusDelayMs,
        statusSequence,
        onStatusRequest: (inFlight) => {
          this.maxInFlightStatusRequests = Math.max(
            this.maxInFlightStatusRequests,
            inFlight,
          );
        },
      }),
    );
    this.trackRequests(worker);
    this.statusDelayMs = statusDelayMs ?? 0;

    this.mounted = render(
      <ScansPageShell
        providers={[]}
        hasManageIngestionsPermission={hasManageIngestionsPermission}
        hasManageScansPermission={hasManageScansPermission}
      >
        <ScanJobsTable data={[]} tab={SCAN_JOBS_TAB.ACTIVE} />
      </ScansPageShell>,
    );
  }

  async leaveScansPage(): Promise<void> {
    const mounted = await this.mounted;
    if (!mounted) throw new Error("leaveScansPage: the page is not mounted");
    mounted.unmount();
    this.mounted = null;
  }

  hasImportFindingsAction(): boolean {
    return this.buttonByText(/Import Findings/) !== null;
  }

  async openImportFindings(): Promise<void> {
    await this.clickButton(/Import Findings/);
    await this.waitForText(/Import findings/i);
  }

  async selectFile(file: File): Promise<void> {
    const input = await this.waitFor(() =>
      this.container.querySelector<HTMLInputElement>('input[type="file"]'),
    );
    await this.user.upload(input, file);
  }

  async dropFile(file: File): Promise<void> {
    await this.attemptDrop(file);
    await this.waitFor(() =>
      this.q('[data-testid="import-findings-dropzone"]')?.textContent?.includes(
        file.name,
      ),
    );
  }

  /** Drop without waiting for the file to be taken: dropFile hangs on a refused drop. */
  async attemptDrop(file: File): Promise<void> {
    const dropzone = await this.waitFor(() =>
      this.q('[data-testid="import-findings-dropzone"] [role="button"]'),
    );
    const dataTransfer = new DataTransfer();
    dataTransfer.items.add(file);
    dropzone.dispatchEvent(
      new DragEvent("drop", { bubbles: true, dataTransfer }),
    );
  }

  /** Both halves matter: drop and keyboard gate on the zone, the file picker on the input. */
  isDropzoneFrozen(): boolean {
    const zone = this.q(
      '[data-testid="import-findings-dropzone"] [role="button"]',
    );
    const input = this.container.querySelector<HTMLInputElement>(
      '[data-testid="import-findings-dropzone"] input[type="file"]',
    );
    return (
      zone?.getAttribute("aria-disabled") === "true" && input?.disabled === true
    );
  }

  async activateDropzoneWithKeyboard(): Promise<boolean> {
    const dropzone = await this.waitFor(() =>
      this.q('[data-testid="import-findings-dropzone"] [role="button"]'),
    );
    const input = await this.waitFor(() =>
      this.container.querySelector<HTMLInputElement>('input[type="file"]'),
    );
    let opened = false;
    input.addEventListener("click", () => {
      opened = true;
    });

    dropzone.focus();
    await this.user.keyboard("[Enter]");
    return opened;
  }

  isImportEnabled(): boolean {
    return !this.buttonByText(/Start import/i)?.disabled;
  }

  async waitForValidationMessage(message: RegExp): Promise<void> {
    await this.waitForText(message);
  }

  async waitForUploadError(message: RegExp): Promise<void> {
    await this.waitForText(message);
  }

  async waitForUploadInProgress(): Promise<void> {
    await this.waitFor(
      () => this.buttonByText(/Importing/i),
      5000,
      "the upload to report progress",
    );
  }

  isUploadInProgress(): boolean {
    const submit = this.buttonByText(/Importing/i);
    return submit !== null && submit.disabled;
  }

  async closeImportFindings(): Promise<void> {
    await this.user.keyboard("[Escape]");
    await this.waitFor(() =>
      this.q('[role="dialog"]') === null ? true : null,
    );
  }

  selectedFileName(): string | null {
    const dropzone = this.q('[data-testid="import-findings-dropzone"]');
    return dropzone?.textContent?.match(/[^\s]+\.json/i)?.[0] ?? null;
  }

  async submitImport(): Promise<void> {
    await this.clickButton(/Start import/i);
  }

  async retryUpload(): Promise<void> {
    await this.clickButton(/Retry import/i);
    await this.waitFor(() => (this.ingestionPostCount === 2 ? true : null));
  }

  /** Anchored on "Import completed": the failed summary reports the same counters. */
  async waitForCompletedSummary(): Promise<void> {
    const { processedRecords, totalRecords, invalidRecords } = this.fixture;
    await this.waitForText(
      new RegExp(
        `Import completed: ${totalRecords} total records, ${processedRecords} processed, ${invalidRecords} invalid`,
        "i",
      ),
      15000,
    );
  }

  hasCompletionNotification(): boolean {
    return this.containsText(/Findings import completed/i);
  }

  hasCompletedSummary(): boolean {
    return this.containsText(/Import completed:/i);
  }

  hasDuplicateImportWarning(): boolean {
    return this.containsText(/The abandoned import may still be running/i);
  }

  async waitForCompletionNotification(): Promise<void> {
    await this.waitFor(
      () => this.hasCompletionNotification(),
      15000,
      "the import completion notification",
    );
  }

  async waitForTrackingStatus(): Promise<void> {
    await this.waitForText(/Import is processing/i);
  }

  async waitForStatusError(): Promise<void> {
    await this.waitForText(/Unable to retrieve the import status/i, 15000);
  }

  async waitForFailedImport(): Promise<void> {
    await this.waitForText(/Import failed/i, 15000);
  }

  async waitForFailedImportSummary(): Promise<void> {
    const { processedRecords, totalRecords, invalidRecords } = this.fixture;
    await this.waitForText(
      new RegExp(
        `${processedRecords} of ${totalRecords} records processed, ${invalidRecords} invalid`,
        "i",
      ),
      15000,
    );
  }

  async retryStatus(): Promise<void> {
    await this.clickButton(/Retry status/i);
    await this.waitFor(() =>
      this.ingestionStatusPollCount >= 2 ? true : null,
    );
  }

  async waitForFirstStatusPoll(): Promise<void> {
    await this.waitFor(
      () => this.ingestionStatusPollCount >= 1,
      5000,
      "the first status poll",
    );
  }

  /** Outlast an uncancelled poll: its response lands, then the modal's 5s interval passes and the next would fire. */
  async waitPastTheNextPoll(): Promise<void> {
    await this.waitForTransition(this.statusDelayMs + 5700);
  }

  async stopTracking(): Promise<void> {
    await this.clickButton(/Stop tracking and start over/i);
    await this.waitFor(
      () => !this.containsText(/Unable to retrieve the import status/i),
      5000,
      "the stuck import to be abandoned",
    );
  }

  get ingestionPostCount(): number {
    return this.countRequests("POST", "/api/ingestions");
  }

  get ingestionStatusPollCount(): number {
    return this.countRequests("GET", "/api/ingestions/");
  }

  get maximumInFlightStatusRequests(): number {
    return this.maxInFlightStatusRequests;
  }

  /** A page refresh is the only thing that brings an imported scan into the table. */
  get pageRefreshCount(): number {
    return vi.mocked(readMockedRouter().refresh).mock.calls.length;
  }

  async uploadedFileName(): Promise<string | null> {
    const entry = [...this.requestLog]
      .reverse()
      .find(
        (request) =>
          request.method === "POST" &&
          new URL(request.url).pathname === "/api/ingestions",
      );
    if (!entry) return null;

    const file = (await entry.request.formData()).get("file");
    return file instanceof File ? file.name : null;
  }
}
