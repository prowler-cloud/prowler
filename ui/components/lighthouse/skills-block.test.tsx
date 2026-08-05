import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { LighthouseSkillsBlock } from "@/components/lighthouse/skills-block";

describe("LighthouseSkillsBlock", () => {
  it("should render every skill with its description", () => {
    // Given / When
    render(
      <LighthouseSkillsBlock onLaunchSkill={vi.fn()} onAskAnything={vi.fn()} />,
    );

    // Then
    expect(screen.getByText("Lighthouse AI Skills")).toBeInTheDocument();
    expect(screen.getByText("Investigate blast radius")).toBeInTheDocument();
    expect(screen.getByText("Verify exploitability")).toBeInTheDocument();
    expect(screen.getByText("Generate remediation")).toBeInTheDocument();
    expect(screen.getByText("Triage & draft ticket")).toBeInTheDocument();
    expect(
      screen.getByText("Check real-world exposure and attack preconditions"),
    ).toBeInTheDocument();
  });

  it("should launch the clicked skill", () => {
    // Given
    const onLaunchSkill = vi.fn();
    render(
      <LighthouseSkillsBlock
        onLaunchSkill={onLaunchSkill}
        onAskAnything={vi.fn()}
      />,
    );

    // When
    fireEvent.click(
      screen.getByRole("button", { name: /Verify exploitability/ }),
    );

    // Then
    expect(onLaunchSkill).toHaveBeenCalledOnce();
    expect(onLaunchSkill.mock.calls[0][0]).toMatchObject({
      id: "verify-exploitability",
    });
  });

  it("should keep the free-form fallback available", () => {
    // Given
    const onAskAnything = vi.fn();
    render(
      <LighthouseSkillsBlock
        onLaunchSkill={vi.fn()}
        onAskAnything={onAskAnything}
      />,
    );

    // When
    fireEvent.click(
      screen.getByRole("button", {
        name: /ask Lighthouse anything about this finding/i,
      }),
    );

    // Then
    expect(onAskAnything).toHaveBeenCalledOnce();
  });
});
