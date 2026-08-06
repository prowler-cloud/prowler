import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import {
  createInitialLighthouseV2StreamState,
  reduceLighthouseV2Event,
} from "@/app/(prowler)/lighthouse/_lib/event-reducer";
import { getSkillById } from "@/lib/lighthouse/skills/registry";

import { SkillRunProgress } from "./skill-run-progress";

function buildStreamState() {
  let state = createInitialLighthouseV2StreamState("task-1", true);
  state = reduceLighthouseV2Event(state, {
    type: "message.delta",
    content: "[[step:1]]Gathering context.",
  });
  state = reduceLighthouseV2Event(state, {
    type: "tool_call.start",
    toolCallId: "tool-1",
    toolName: "get_finding",
  });
  state = reduceLighthouseV2Event(state, {
    type: "tool_call.end",
    toolCallId: "tool-1",
    outcome: "success",
  });
  state = reduceLighthouseV2Event(state, {
    type: "message.delta",
    content: "[[step:3]]Checking public exposure.",
  });
  state = reduceLighthouseV2Event(state, {
    type: "tool_call.start",
    toolCallId: "tool-2",
    toolName: "check_public_exposure",
  });
  return state;
}

const skill = (() => {
  const definition = getSkillById("verify-exploitability");
  if (!definition) throw new Error("Expected skill definition");
  return definition;
})();

describe("SkillRunProgress", () => {
  it("should show the compact progress card with the current step", () => {
    // Given / When
    render(<SkillRunProgress skill={skill} streamState={buildStreamState()} />);

    // Then
    expect(screen.getByText("Verify exploitability")).toBeInTheDocument();
    expect(
      screen.getByText("Step 3 of 5 · Check public exposure & trust policy"),
    ).toBeInTheDocument();
    // Compact by default: the full timeline is not expanded yet.
    expect(
      screen.queryByText("Query attack paths for lateral movement"),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("progressbar")).toHaveAttribute(
      "data-slot",
      "progress",
    );
  });

  it("should expand into the step timeline with tool chips nested under steps", async () => {
    // Given
    const user = userEvent.setup();
    render(<SkillRunProgress skill={skill} streamState={buildStreamState()} />);

    // When
    await user.click(
      screen.getByRole("button", { name: /Verify exploitability/ }),
    );

    // Then: every workflow step is listed
    for (const step of skill.steps) {
      expect(screen.getByText(step)).toBeInTheDocument();
    }
    // Tools appear as chips under their step, in the repo's humanized format
    expect(screen.getByText("Get finding")).toBeInTheDocument();
    expect(screen.getByText("Check public exposure")).toBeInTheDocument();
  });

  it("should clamp out-of-range tool steps onto the last real step", async () => {
    // Given: a marker beyond the skill's five steps tags the tool with step 99
    const user = userEvent.setup();
    let state = createInitialLighthouseV2StreamState("task-1", true);
    state = reduceLighthouseV2Event(state, {
      type: "message.delta",
      content: "[[step:99]]Wrapping up.",
    });
    state = reduceLighthouseV2Event(state, {
      type: "tool_call.start",
      toolCallId: "tool-1",
      toolName: "get_finding",
    });
    render(<SkillRunProgress skill={skill} streamState={state} />);

    // When
    await user.click(
      screen.getByRole("button", { name: /Verify exploitability/ }),
    );

    // Then: the tool chip still lands under a rendered step instead of vanishing
    expect(screen.getByText("Get finding")).toBeInTheDocument();
  });

  it("should show a preparing state before the first step marker arrives", () => {
    // Given / When
    render(
      <SkillRunProgress
        skill={skill}
        streamState={createInitialLighthouseV2StreamState("task-1")}
      />,
    );

    // Then
    expect(screen.getByText("Preparing workflow…")).toBeInTheDocument();
  });
});
