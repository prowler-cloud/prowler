import { describe, expect, it } from "vitest";

import type { AttackPathScan, ScanState } from "@/types/attack-paths";

import {
  ATTACK_PATHS_VIEW_STATES,
  getAttackPathsViewState,
  getGraphBuildingProgress,
} from "./get-attack-paths-view-state";

const scan = (
  state: ScanState,
  graph_data_ready: boolean,
  progress = 0,
): AttackPathScan => ({
  type: "attack-paths-scans",
  id: `${state}-${String(graph_data_ready)}-${progress}`,
  attributes: {
    state,
    progress,
    graph_data_ready,
    provider_alias: "Provider",
    provider_type: "aws",
    provider_uid: "123456789012",
    inserted_at: "2026-04-21T10:00:00Z",
    started_at: "2026-04-21T10:00:00Z",
    completed_at: null,
    duration: null,
  },
  relationships: {
    provider: { data: { type: "providers", id: "p" } },
    scan: { data: { type: "scans", id: "s" } },
    task: { data: { type: "tasks", id: "t" } },
  },
});

describe("getAttackPathsViewState", () => {
  it("returns loading while scans are loading, regardless of other inputs", () => {
    expect(
      getAttackPathsViewState({
        scansLoading: true,
        loadError: true,
        scans: [],
      }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.LOADING);
  });

  it("returns error on load failure (error wins over empty scans)", () => {
    expect(
      getAttackPathsViewState({
        scansLoading: false,
        loadError: true,
        scans: [],
      }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.ERROR);
  });

  it("returns no-scans for an empty list", () => {
    expect(
      getAttackPathsViewState({
        scansLoading: false,
        loadError: false,
        scans: [],
      }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.NO_SCANS);
  });

  it("returns ready when any provider has a queryable graph", () => {
    expect(
      getAttackPathsViewState({
        scansLoading: false,
        loadError: false,
        scans: [scan("executing", false, 50), scan("completed", true, 100)],
      }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.READY);
  });

  it("returns graph-building when none ready and some scan is executing (wins over scheduled)", () => {
    expect(
      getAttackPathsViewState({
        scansLoading: false,
        loadError: false,
        scans: [scan("scheduled", false), scan("executing", false, 30)],
      }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.GRAPH_BUILDING);
  });

  it("returns scan-running when none ready and some scan is scheduled/available", () => {
    expect(
      getAttackPathsViewState({
        scansLoading: false,
        loadError: false,
        scans: [scan("scheduled", false)],
      }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.SCAN_RUNNING);
    expect(
      getAttackPathsViewState({
        scansLoading: false,
        loadError: false,
        scans: [scan("available", false)],
      }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.SCAN_RUNNING);
  });

  it("returns no-graph-data when none ready and all scans are terminal", () => {
    expect(
      getAttackPathsViewState({
        scansLoading: false,
        loadError: false,
        scans: [scan("completed", false), scan("failed", false)],
      }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.NO_GRAPH_DATA);
  });
});

describe("getGraphBuildingProgress", () => {
  it("returns the max progress among executing scans", () => {
    expect(
      getGraphBuildingProgress([
        scan("executing", false, 30),
        scan("executing", false, 70),
        scan("scheduled", false, 99),
      ]),
    ).toBe(70);
  });

  it("returns 0 when no scan is executing", () => {
    expect(getGraphBuildingProgress([scan("scheduled", false, 50)])).toBe(0);
  });
});
