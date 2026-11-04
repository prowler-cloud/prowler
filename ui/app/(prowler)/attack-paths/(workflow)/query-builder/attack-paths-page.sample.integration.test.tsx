import { beforeEach, describe, expect, it, vi } from "vitest";

import { render } from "@/__tests__/render-browser";
import { SAMPLE_ATTACK_PATHS } from "@/lib/sample-preview/sample-attack-paths";
import { failedSampleFindings } from "@/lib/sample-preview/sample-records";
import { useLighthouseContextStore } from "@/store/lighthouse-context/store";
import { resetLighthouseContextStore } from "@/store/lighthouse-context/store.test-utils";

const actions = vi.hoisted(() => ({
  getAttackPathScans: vi.fn(),
  getAvailableQueries: vi.fn(),
  executeQuery: vi.fn(),
  executeCustomQuery: vi.fn(),
  getFindingById: vi.fn(),
}));

vi.mock("@/actions/attack-paths", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/actions/attack-paths")>()),
  getAttackPathScans: actions.getAttackPathScans,
  getAvailableQueries: actions.getAvailableQueries,
  executeQuery: actions.executeQuery,
  executeCustomQuery: actions.executeCustomQuery,
}));

vi.mock("@/actions/findings", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/actions/findings")>()),
  getFindingById: actions.getFindingById,
}));

import { useGraphStore } from "./_hooks/use-graph-state";
import AttackPathsPage from "./attack-paths-page";
import { AttackPathPageHarness } from "./attack-paths-page.harness";

const SAMPLE_FIXTURE = {
  scans: [SAMPLE_ATTACK_PATHS.scan],
  scanId: SAMPLE_ATTACK_PATHS.scan.id,
  queries: [SAMPLE_ATTACK_PATHS.query],
  queryId: SAMPLE_ATTACK_PATHS.query.id,
  queryResult: SAMPLE_ATTACK_PATHS.result,
};

const [BUCKET_FINDING] = failedSampleFindings("s3_bucket_public_access");
const [INSTANCE_FINDING] = failedSampleFindings("ec2_instance_imdsv2_enabled");

beforeEach(() => {
  actions.getFindingById.mockReset();
  useGraphStore.getState().reset();
  resetLighthouseContextStore();
  window.history.replaceState({}, "", "/attack-paths");
});

describe("Attack Paths sample preview", () => {
  it("shows the sample graph, opens its findings and keeps it off the API and Lighthouse", async () => {
    // Given
    const screen = await render(
      <AttackPathsPage sample={SAMPLE_ATTACK_PATHS} />,
    );
    const graph = new AttackPathPageHarness(SAMPLE_FIXTURE);

    await expect
      .element(screen.getByRole("radio", { name: "Selected scan" }))
      .toBeDisabled();

    // When
    await vi.waitFor(
      () => expect(graph.getNodeById("sample-s3-exports")).not.toBeNull(),
      {
        timeout: 10000,
      },
    );
    await graph.clickNode("sample-s3-exports");
    await vi.waitFor(() =>
      expect(graph.getNodeById(BUCKET_FINDING.id)).not.toBeNull(),
    );
    await graph.clickNode(BUCKET_FINDING.id);
    // The finding drawer resolves the sample record through the read action.
    await vi.waitFor(() =>
      expect(actions.getFindingById).toHaveBeenCalledWith(
        BUCKET_FINDING.id,
        expect.anything(),
      ),
    );
    await graph.executeQuery({ selectFirst: false });

    // Then
    expect(graph.showsNodeLabel(INSTANCE_FINDING.resource.name)).toBe(true);
    expect(
      graph.showsNodeLabel(SAMPLE_ATTACK_PATHS.query.attributes.name),
    ).toBe(true);
    expect(actions.getAttackPathScans).not.toHaveBeenCalled();
    expect(actions.getAvailableQueries).not.toHaveBeenCalled();
    expect(actions.executeQuery).not.toHaveBeenCalled();
    expect(
      useLighthouseContextStore.getState().contributions["attack-path-current"],
    ).toBeUndefined();
  });
});
