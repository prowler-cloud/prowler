import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { LighthouseSkillsRail } from "./lighthouse-skills-rail";

describe("LighthouseSkillsRail", () => {
  it("should render a launch chip per enabled skill and none for disabled ones", () => {
    // Given / When
    render(
      <LighthouseSkillsRail onLaunchSkill={vi.fn()} onSubmitPrompt={vi.fn()} />,
    );

    // Then
    expect(screen.getByText("Skills")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Contextual Fix" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Triage Decision" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Systemic Scope" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Compliance Impact/ }),
    ).not.toBeInTheDocument();
  });

  it("should launch a skill directly from its chip", async () => {
    // Given
    const user = userEvent.setup();
    const onLaunchSkill = vi.fn();
    render(
      <LighthouseSkillsRail
        onLaunchSkill={onLaunchSkill}
        onSubmitPrompt={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Triage Decision" }));

    // Then
    expect(onLaunchSkill).toHaveBeenCalledOnce();
    expect(onLaunchSkill.mock.calls[0][0]).toMatchObject({
      id: "triage-decision",
    });
  });

  it("should list the full catalog in the menu with a recommended lead", async () => {
    // Given
    const user = userEvent.setup();
    const onLaunchSkill = vi.fn();
    render(
      <LighthouseSkillsRail
        onLaunchSkill={onLaunchSkill}
        onSubmitPrompt={vi.fn()}
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: "More Lighthouse skills" }),
    );

    // Then — every skill shows, the first enabled one leads as Recommended
    // (description included), and disabled ones stay dimmed as coming soon.
    expect(screen.getByText("Recommended")).toBeInTheDocument();
    const recommended = screen.getByRole("menuitem", {
      name: /Contextual Fix/,
    });
    expect(recommended).toHaveTextContent("Give me the fix for this finding");
    expect(
      screen.getByRole("menuitem", { name: /Triage Decision/ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("menuitem", { name: /Systemic Scope/ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("menuitem", { name: /Compliance Impact/ }),
    ).toHaveAttribute("aria-disabled", "true");

    // When — launching from a menu item works like the chips.
    await user.click(screen.getByRole("menuitem", { name: /Systemic Scope/ }));

    // Then
    expect(onLaunchSkill).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ id: "systemic-scope" }),
    );
  });

  it("should submit the typed prompt, clear it and close the menu", async () => {
    // Given
    const user = userEvent.setup();
    const onSubmitPrompt = vi.fn();
    render(
      <LighthouseSkillsRail
        onLaunchSkill={vi.fn()}
        onSubmitPrompt={onSubmitPrompt}
      />,
    );
    await user.click(
      screen.getByRole("button", { name: "More Lighthouse skills" }),
    );

    // When
    const input = screen.getByRole("textbox", {
      name: "Ask Lighthouse anything",
    });
    await user.type(input, "Is this reachable from the internet?{Enter}");

    // Then
    expect(onSubmitPrompt).toHaveBeenCalledExactlyOnceWith(
      "Is this reachable from the internet?",
    );
    expect(
      screen.queryByRole("menuitem", { name: /Compliance Impact/ }),
    ).not.toBeInTheDocument();
  });

  it("should ignore whitespace-only prompts and keep the menu open", async () => {
    // Given
    const user = userEvent.setup();
    const onSubmitPrompt = vi.fn();
    render(
      <LighthouseSkillsRail
        onLaunchSkill={vi.fn()}
        onSubmitPrompt={onSubmitPrompt}
      />,
    );
    await user.click(
      screen.getByRole("button", { name: "More Lighthouse skills" }),
    );

    // When
    const input = screen.getByRole("textbox", {
      name: "Ask Lighthouse anything",
    });
    await user.type(input, "   {Enter}");

    // Then
    expect(onSubmitPrompt).not.toHaveBeenCalled();
    expect(
      screen.getByRole("menuitem", { name: /Compliance Impact/ }),
    ).toBeInTheDocument();
  });

  it("should keep typed letters in the prompt instead of feeding menu typeahead", async () => {
    // Given
    const user = userEvent.setup();
    const onLaunchSkill = vi.fn();
    render(
      <LighthouseSkillsRail
        onLaunchSkill={onLaunchSkill}
        onSubmitPrompt={vi.fn()}
      />,
    );
    await user.click(
      screen.getByRole("button", { name: "More Lighthouse skills" }),
    );

    // When — "C" is Compliance Impact's typeahead prefix.
    const input = screen.getByRole("textbox", {
      name: "Ask Lighthouse anything",
    });
    await user.type(input, "Compliance{Enter}");

    // Then
    expect(onLaunchSkill).not.toHaveBeenCalled();
  });
});
