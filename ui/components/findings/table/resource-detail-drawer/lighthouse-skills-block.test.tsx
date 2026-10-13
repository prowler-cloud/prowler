import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { LighthouseSkillsBlock } from "./lighthouse-skills-block";

describe("LighthouseSkillsBlock", () => {
  it("should render every skill with its description", () => {
    // Given / When
    render(
      <LighthouseSkillsBlock onLaunchSkill={vi.fn()} onAskAnything={vi.fn()} />,
    );

    // Then
    expect(screen.getByText("Lighthouse AI Skills")).toBeInTheDocument();
    expect(screen.getByText("Contextual Fix")).toBeInTheDocument();
    expect(screen.getByText("Triage Decision")).toBeInTheDocument();
    expect(screen.getByText("Systemic Scope")).toBeInTheDocument();
    expect(screen.getByText("Compliance Impact")).toBeInTheDocument();
    expect(
      screen.getByText("Is this real, and if not, close it out"),
    ).toBeInTheDocument();
  });

  it("should launch the clicked skill", async () => {
    // Given
    const user = userEvent.setup();
    const onLaunchSkill = vi.fn();
    render(
      <LighthouseSkillsBlock
        onLaunchSkill={onLaunchSkill}
        onAskAnything={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: /Triage Decision/ }));

    // Then
    expect(onLaunchSkill).toHaveBeenCalledOnce();
    expect(onLaunchSkill.mock.calls[0][0]).toMatchObject({
      id: "triage-decision",
    });
  });

  it("should render disabled skills as coming soon and not launch them", async () => {
    // Given
    const user = userEvent.setup();
    const onLaunchSkill = vi.fn();
    render(
      <LighthouseSkillsBlock
        onLaunchSkill={onLaunchSkill}
        onAskAnything={vi.fn()}
      />,
    );

    // Then
    const card = screen.getByRole("button", { name: /Compliance Impact/ });
    expect(card).toBeDisabled();
    expect(screen.getByText("Coming soon")).toBeInTheDocument();

    // When
    await user.click(card);

    // Then
    expect(onLaunchSkill).not.toHaveBeenCalled();
  });

  it("should keep the free-form fallback available", async () => {
    // Given
    const user = userEvent.setup();
    const onAskAnything = vi.fn();
    render(
      <LighthouseSkillsBlock
        onLaunchSkill={vi.fn()}
        onAskAnything={onAskAnything}
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", {
        name: /ask Lighthouse anything about this finding/i,
      }),
    );

    // Then
    expect(onAskAnything).toHaveBeenCalledOnce();
  });
});
