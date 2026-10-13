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
  let state = createInitialLighthouseV2StreamState("task-1");
  state = reduceLighthouseV2Event(state, {
    type: "message.delta",
    content: "Gathering context.",
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
    type: "tool_call.start",
    toolCallId: "tool-2",
    toolName: "check_public_exposure",
  });
  return state;
}

const skill = (() => {
  const definition = getSkillById("triage-decision");
  if (!definition) throw new Error("Expected skill definition");
  return definition;
})();

describe("SkillRunProgress", () => {
  it("should surface the running tool as the live activity", () => {
    // Given / When
    render(<SkillRunProgress skill={skill} streamState={buildStreamState()} />);

    // Then
    expect(screen.getByText("Triage Decision")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(
      "Running Check public exposure…",
    );
  });

  it("should show a thinking state while no tool is running", () => {
    // Given: narration only — repeating the skill name here would duplicate
    // the card title right above
    let state = createInitialLighthouseV2StreamState("task-1");
    state = reduceLighthouseV2Event(state, {
      type: "message.delta",
      content: "Composing the verdict.",
    });

    // When
    render(<SkillRunProgress skill={skill} streamState={state} />);

    // Then
    expect(screen.getByRole("status")).toHaveTextContent("Thinking…");
  });

  it("should expand into the timeline of tools as they actually ran", async () => {
    // Given
    const user = userEvent.setup();
    render(<SkillRunProgress skill={skill} streamState={buildStreamState()} />);

    // When
    await user.click(screen.getByRole("button", { name: /Triage Decision/ }));

    // Then: real tool calls in order, humanized
    expect(screen.getByText("Get finding")).toBeInTheDocument();
    expect(screen.getByText("Check public exposure")).toBeInTheDocument();
  });

  it("should stream narration and tool activity in order below the card", () => {
    // Given / When
    render(<SkillRunProgress skill={skill} streamState={buildStreamState()} />);

    // Then: the narration block is followed by the tool group it announced,
    // matching how the persisted message renders after the run.
    expect(screen.getByText("Gathering context.")).toBeInTheDocument();
    expect(screen.getByText("Using tools")).toBeInTheDocument();
  });
});
