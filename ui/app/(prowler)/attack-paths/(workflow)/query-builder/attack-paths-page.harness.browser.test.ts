import { describe, expect, it, vi } from "vitest";

import { fixtures } from "./attack-paths-page.fixtures";
import { AttackPathPageHarness } from "./attack-paths-page.harness";

describe("AttackPathPageHarness", () => {
  it("should fail graph node clicks when browser pointer interaction fails", async () => {
    // Given - A rendered graph node whose pointer interaction fails
    const harness = new AttackPathPageHarness(fixtures.typical());
    const node = document.createElement("div");
    node.className = "react-flow__node react-flow__node-resource";
    node.setAttribute("data-id", "ec2-1");
    document.body.append(node);

    const pointerError = new Error("pointer intercepted");
    const clickSpy = vi
      .spyOn(harness.user, "click")
      .mockRejectedValue(pointerError);
    const domClickSpy = vi.spyOn(node, "click");

    // When / Then
    await expect(harness.clickNode("ec2-1")).rejects.toThrow(
      "pointer intercepted",
    );
    expect(clickSpy).toHaveBeenCalledWith(node);
    expect(domClickSpy).not.toHaveBeenCalled();
  });

  it("should dispatch rapid finding clicks synchronously for race tests", async () => {
    // Given - A rendered finding node and a harness rapid-click helper
    const harness = new AttackPathPageHarness(fixtures.typical());
    const finding = document.createElement("button");
    finding.className = "react-flow__node react-flow__node-finding";
    finding.setAttribute("data-id", "f-1");
    document.body.append(finding);

    const userClickSpy = vi.spyOn(harness.user, "click");
    const domClickSpy = vi.spyOn(finding, "click");
    vi.spyOn(harness, "waitForTransition").mockResolvedValue();

    // When
    await harness.rapidlyClickFirstFindingNode(2);

    // Then
    expect(userClickSpy).not.toHaveBeenCalled();
    expect(domClickSpy).toHaveBeenCalledTimes(2);
  });
});
