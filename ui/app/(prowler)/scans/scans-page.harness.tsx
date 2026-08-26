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

    render(
      <ScansPageShell
        providers={[]}
        hasManageIngestionsPermission={hasManageIngestionsPermission}
        hasManageScansPermission={hasManageScansPermission}
      >
        <ScanJobsTable data={[]} tab={SCAN_JOBS_TAB.ACTIVE} />
      </ScansPageShell>,
    );
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

  /** Drop a file without waiting for it to be taken: a frozen zone refuses it. */
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

  /**
   * Whether the zone refuses a new file. Both halves matter: the drop and
   * keyboard paths gate on the zone, the file picker on the input itself.
   */
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

  /**
   * The counters the completed job reported. Anchored on "Import completed" —
   * the failed summary reports the very same numbers, so the counters alone
   * cannot tell the two outcomes apart.
   */
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

  async waitForCompletionNotification(): Promise<void> {
    await this.waitForText(/Findings import completed/i, 15000);
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

  /** The record counters the service reported for the job that failed. */
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

  get ingestionPostCount(): number {
    return this.countRequests("POST", "/api/ingestions");
  }

  get ingestionStatusPollCount(): number {
    return this.countRequests("GET", "/api/ingestions/");
  }

  get maximumInFlightStatusRequests(): number {
    return this.maxInFlightStatusRequests;
  }

  /**
   * How many times the page asked for its server data again — the only thing
   * that brings an imported scan into the table, since the table's own refresh
   * only polls while a scan is already executing.
   *
   * `next/navigation` is mocked suite-wide (`vitest.integration.setup.ts`) and
   * hands out one router, so its `refresh` spy is the whole page's history.
   */
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
