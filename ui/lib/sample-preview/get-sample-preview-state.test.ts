import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { authMock } = vi.hoisted(() => ({
  authMock: vi.fn(),
}));

vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));
vi.mock("@/auth.config", () => ({ auth: authMock }));

import { getSamplePreviewState } from "./get-sample-preview-state";
import { SAMPLE_PREVIEW_STAGE } from "./sample-preview-state";

interface ApiAnswers {
  completedScans?: Response;
  providers?: Response;
  runningScans?: Response;
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/vnd.api+json" },
  });

const rows = (...data: unknown[]) => json({ data });

const sessionWith = (manageProviders: boolean) => ({
  accessToken: "token",
  user: { permissions: { manage_providers: manageProviders } },
});

const fetchMock = vi.fn();

// Routes each lookup by its query, so the real actions and adapters run.
const answerWith = ({
  completedScans = rows(),
  providers = rows(),
  runningScans = rows(),
}: ApiAnswers) => {
  fetchMock.mockImplementation(async (input: string) => {
    const url = new URL(input);
    if (url.pathname.endsWith("/providers")) return providers;
    if (url.searchParams.get("filter[state]") === "completed") {
      return completedScans;
    }
    return runningScans;
  });
};

describe("getSamplePreviewState", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    authMock.mockResolvedValue(sessionWith(true));
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("never shows the sample in Local Server, without asking the API", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    answerWith({});

    // When
    const state = await getSamplePreviewState();

    // Then
    expect(state).toEqual({ active: false });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows the real page when the scans endpoint fails with a server error", async () => {
    // Given
    answerWith({ completedScans: json({ errors: [] }, 503) });

    // When
    const state = await getSamplePreviewState();

    // Then
    expect(state).toEqual({ active: false });
  });

  it("shows the real page after one lookup when the tenant has a completed scan", async () => {
    // Given
    answerWith({ completedScans: rows({ id: "scan-1", attributes: {} }) });

    // When
    const state = await getSamplePreviewState();

    // Then
    expect(state).toEqual({ active: false });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("shows the sample to a new tenant's admin who has not connected a provider", async () => {
    // Given
    answerWith({});

    // When
    const state = await getSamplePreviewState();

    // Then
    expect(state).toEqual({
      active: true,
      stage: SAMPLE_PREVIEW_STAGE.NO_PROVIDER,
      runningScan: null,
    });
  });

  it("shows the real page to a user who cannot manage providers", async () => {
    // Given: limited-visibility users list zero providers in a tenant that is not empty.
    authMock.mockResolvedValue(sessionWith(false));
    answerWith({});

    // When
    const state = await getSamplePreviewState();

    // Then
    expect(state).toEqual({ active: false });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("tracks the first scan while it runs", async () => {
    // Given
    answerWith({
      providers: rows({ id: "provider-1", attributes: {} }),
      runningScans: rows({ id: "scan-1", attributes: { progress: 43 } }),
    });

    // When
    const state = await getSamplePreviewState();

    // Then
    expect(state).toEqual({
      active: true,
      stage: SAMPLE_PREVIEW_STAGE.SCAN_RUNNING,
      runningScan: { id: "scan-1", progress: 43 },
    });
  });
});
