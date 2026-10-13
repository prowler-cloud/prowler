import { describe, expect, it } from "vitest";

import { getSkillById } from "@/lib/lighthouse/skills/registry";
import type { LighthouseContextEnvelope } from "@/types/lighthouse-context";

import {
  buildOptimisticMessage,
  getLighthouseContext,
  getSkillRef,
  getTextContent,
} from "./messages";

describe("getTextContent", () => {
  it("should prefer display_text over the agent-facing technical text", () => {
    // Given
    const content = {
      text: "[PROWLER_UI_CONTEXT_V1]\nmetadata\n[/PROWLER_UI_CONTEXT_V1]\n\nQuestion",
      display_text: "Question",
    };

    // When
    const text = getTextContent(content);

    // Then
    expect(text).toBe("Question");
  });

  it("should preserve legacy text-only content", () => {
    // Given / When
    const text = getTextContent({ text: "Legacy question" });

    // Then
    expect(text).toBe("Legacy question");
  });
});

describe("getLighthouseContext", () => {
  it("should normalize valid persisted UI context", () => {
    // Given
    const content = {
      text: "technical prompt",
      display_text: "Question",
      ui_context: {
        schema_version: 1,
        transport: "inline",
        items: [
          {
            kind: "page",
            id: "findings",
            source: "automatic",
            scope_key: "findings:/findings",
            label: "Findings",
            path: "/findings",
          },
        ],
      },
    };

    // When
    const context = getLighthouseContext(content);

    // Then
    expect(context).toEqual({
      schemaVersion: 1,
      transport: "inline",
      items: [
        {
          kind: "page",
          id: "findings",
          source: "automatic",
          scopeKey: "findings:/findings",
          label: "Findings",
          path: "/findings",
        },
      ],
    });
  });

  it("should ignore corrupt persisted UI context", () => {
    // Given / When
    const context = getLighthouseContext({
      text: "Question",
      ui_context: { schema_version: 99, items: "invalid" },
    });

    // Then
    expect(context).toBeUndefined();
  });
});

describe("buildOptimisticMessage", () => {
  it("should keep display text and the original context snapshot", () => {
    // Given
    const context: LighthouseContextEnvelope = {
      schemaVersion: 1,
      transport: "inline",
      items: [
        {
          kind: "page",
          id: "findings",
          source: "automatic",
          scopeKey: "findings:/findings",
          label: "Findings",
          path: "/findings",
        },
      ],
    };

    // When
    const message = buildOptimisticMessage(
      "user",
      "Prioritize findings",
      context,
    );

    // Then
    expect(message.parts[0]?.content).toMatchObject({
      text: expect.stringContaining("[PROWLER_UI_CONTEXT_V1]"),
      display_text: "Prioritize findings",
      ui_context: expect.objectContaining({ schema_version: 1 }),
    });
  });

  it("should embed the skill instructions and the ui_skill ref when a skill launches", () => {
    // Given
    const skill = getSkillById("triage-decision");
    if (!skill) throw new Error("Expected skill definition");

    // When
    const message = buildOptimisticMessage(
      "user",
      skill.name,
      undefined,
      skill,
    );

    // Then
    expect(message.parts[0]?.content).toMatchObject({
      text: expect.stringContaining("[PROWLER_UI_SKILL_V1]"),
      display_text: "Triage Decision",
      ui_skill: {
        skill_id: "triage-decision",
        name: "Triage Decision",
        version: 1,
      },
    });
  });
});

describe("getSkillRef", () => {
  it("should normalize a persisted ui_skill ref", () => {
    // Given / When
    const ref = getSkillRef({
      text: "prompt",
      display_text: "Triage Decision",
      ui_skill: {
        skill_id: "triage-decision",
        name: "Triage Decision",
        version: 1,
      },
    });

    // Then
    expect(ref).toEqual({
      skillId: "triage-decision",
      name: "Triage Decision",
      version: 1,
    });
  });

  it("should ignore content without a valid ui_skill", () => {
    expect(getSkillRef({ text: "plain" })).toBeUndefined();
    expect(
      getSkillRef({ text: "x", ui_skill: { skill_id: 4 } }),
    ).toBeUndefined();
    expect(getSkillRef("string content")).toBeUndefined();
  });
});
