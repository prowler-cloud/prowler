import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { authMock } = vi.hoisted(() => ({
  authMock: vi.fn(),
}));

vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));
vi.mock("@/auth.config", () => ({ auth: authMock }));

import {
  SAMPLE_PREVIEW_STAGE,
  type SamplePreviewActive,
} from "@/lib/sample-preview/sample-preview-state";

import { shouldShowFindingsSample } from "./should-show-findings-sample";

const RUNNING_SCAN_ID = "11111111-1111-4111-8111-111111111111";

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/vnd.api+json" },
  });

// A Response body is read once, so every lookup gets a fresh one.
const runningScan = () =>
  json({
    data: {
      type: "scans",
      id: RUNNING_SCAN_ID,
      attributes: {
        state: "executing",
        started_at: "2026-11-04T10:00:00Z",
        completed_at: null,
      },
    },
  });

const finding = { type: "findings", id: "f-1", attributes: {} };

const scanRunning: SamplePreviewActive = {
  active: true,
  stage: SAMPLE_PREVIEW_STAGE.SCAN_RUNNING,
  runningScan: { id: RUNNING_SCAN_ID, progress: 12 },
};

const fetchMock = vi.fn();

// Routes each lookup by its path, so the real actions and adapters run.
const answerWith = ({
  findings,
  scan = runningScan,
}: {
  findings: Response;
  scan?: () => Response;
}) => {
  fetchMock.mockImplementation(async (input: string) => {
    const url = new URL(input);
    if (url.pathname.endsWith(`/scans/${RUNNING_SCAN_ID}`)) {
      return scan();
    }
    if (url.pathname.endsWith("/findings")) return findings;
    throw new Error(`Unexpected request: ${url.pathname}`);
  });
};

const findingsRequest = () =>
  fetchMock.mock.calls
    .map(([input]) => new URL(input as string))
    .find((url) => url.pathname.endsWith("/findings"));

describe("shouldShowFindingsSample", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    vi.useFakeTimers({ toFake: ["Date"] });
    // The scan started yesterday and is still running.
    vi.setSystemTime(new Date("2026-11-05T09:00:00Z"));
    authMock.mockResolvedValue({ accessToken: "token" });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("hands Findings over to the running first scan once it has stored findings", async () => {
    // Given
    answerWith({ findings: json({ data: [finding] }) });

    // When
    const showSample = await shouldShowFindingsSample(scanRunning);

    // Then
    expect(showSample).toBe(false);
    const request = findingsRequest();
    expect(request?.searchParams.get("filter[scan]")).toBe(RUNNING_SCAN_ID);
    // The API rejects findings queries without a date range.
    expect(request?.searchParams.get("filter[inserted_at__gte]")).toBe(
      "2026-11-04",
    );
    expect(request?.searchParams.get("filter[inserted_at__lte]")).toBe(
      "2026-11-05",
    );
  });

  it("keeps the sample while the running scan has not stored any finding yet", async () => {
    // Given
    answerWith({ findings: json({ data: [] }) });

    // When
    const showSample = await shouldShowFindingsSample(scanRunning);

    // Then
    expect(showSample).toBe(true);
  });

  it("keeps the sample when the findings lookup fails", async () => {
    // Given
    answerWith({ findings: json({ errors: [{ detail: "boom" }] }, 503) });

    // When
    const showSample = await shouldShowFindingsSample(scanRunning);

    // Then
    expect(showSample).toBe(true);
  });

  it("keeps the sample when the scan lookup fails with a server error", async () => {
    // Given
    answerWith({
      findings: json({ data: [finding] }),
      scan: () => json({ errors: [{ detail: "boom" }] }, 503),
    });

    // When
    const showSample = await shouldShowFindingsSample(scanRunning);

    // Then
    expect(showSample).toBe(true);
  });

  it("keeps the sample without asking the API before any scan runs", async () => {
    // Given
    answerWith({ findings: json({ data: [finding] }) });

    // When
    const showSample = await shouldShowFindingsSample({
      active: true,
      stage: SAMPLE_PREVIEW_STAGE.NO_SCAN,
      runningScan: null,
    });

    // Then
    expect(showSample).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("never shows the sample when the preview is off", async () => {
    // Given
    answerWith({ findings: json({ data: [] }) });

    // When
    const showSample = await shouldShowFindingsSample({ active: false });

    // Then
    expect(showSample).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
