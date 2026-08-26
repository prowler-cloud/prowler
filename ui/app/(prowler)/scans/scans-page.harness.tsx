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
    const dropzone = await this.waitFor(() =>
      this.q('[data-testid="import-findings-dropzone"] [role="button"]'),
    );
    const dataTransfer = new DataTransfer();
    dataTransfer.items.add(file);
    dropzone.dispatchEvent(
      new DragEvent("drop", { bubbles: true, dataTransfer }),
    );
    await this.waitFor(() =>
      this.q('[data-testid="import-findings-dropzone"]')?.textContent?.includes(
        file.name,
      ),
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

  async waitForCompletedSummary(): Promise<void> {
    await this.waitForText(/3 total|3 records/i, 15000);
    await this.waitForText(/1 invalid/i, 15000);
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
