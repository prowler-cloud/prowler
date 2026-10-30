import { beforeEach, describe, expect, it, vi } from "vitest";

import { render } from "@/__tests__/render-browser";
import { SAMPLE_ATTACK_PATHS } from "@/lib/sample-preview/sample-attack-paths";
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

beforeEach(() => {
  useGraphStore.getState().reset();
  resetLighthouseContextStore();
  window.history.replaceState({}, "", "/attack-paths");
});

describe("Attack Paths sample preview", () => {
  it("shows the sample graph and keeps it off the API and Lighthouse", async () => {
    // Given
    await render(<AttackPathsPage sample={SAMPLE_ATTACK_PATHS} />);
    const graph = new AttackPathPageHarness(SAMPLE_FIXTURE);

    // When
    await vi.waitFor(
      () => expect(graph.getNodeById("sample-s3-exports")).not.toBeNull(),
      {
        timeout: 10000,
      },
    );
    await graph.clickNode("sample-s3-exports");
    await vi.waitFor(() =>
      expect(graph.getNodeById("sample-finding-public-bucket")).not.toBeNull(),
    );
    await graph.clickNode("sample-finding-public-bucket");
    await graph.executeQuery({ selectFirst: false });

    // Then
    expect(graph.showsNodeLabel("bastion-01")).toBe(true);
    expect(
      graph.showsNodeLabel(SAMPLE_ATTACK_PATHS.query.attributes.name),
    ).toBe(true);
    expect(actions.getAttackPathScans).not.toHaveBeenCalled();
    expect(actions.getAvailableQueries).not.toHaveBeenCalled();
    expect(actions.executeQuery).not.toHaveBeenCalled();
    expect(actions.getFindingById).not.toHaveBeenCalled();
    expect(
      useLighthouseContextStore.getState().contributions["attack-path-current"],
    ).toBeUndefined();
  });
});
