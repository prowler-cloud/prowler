import { describe, expect, it } from "vitest";

import { SAMPLE_ATTACK_PATHS } from "./sample-attack-paths";
import { getSampleFinding } from "./sample-records";

const { nodes, relationships = [] } = SAMPLE_ATTACK_PATHS.result;
const findingNodes = nodes.filter((node) =>
  node.labels.includes("ProwlerFinding"),
);

describe("sample attack paths", () => {
  it("opens a sample finding record from every finding node", () => {
    expect(findingNodes.length).toBeGreaterThan(0);
    for (const node of findingNodes) {
      expect(getSampleFinding(node.id)?.status).toBe("FAIL");
    }
  });

  it("hangs each finding off the resource that record names", () => {
    for (const node of findingNodes) {
      const edge = relationships.find((rel) => rel.target === node.id);
      const resource = nodes.find((candidate) => candidate.id === edge?.source);

      expect(resource?.properties.name).toBe(
        getSampleFinding(node.id)?.resource.name,
      );
    }
  });
});
