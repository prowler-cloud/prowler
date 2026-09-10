import { describe, expect, it } from "vitest";

import {
  getAllSkills,
  getLaunchableSkills,
  getNextSkill,
  getSkillById,
} from "./registry";

describe("skills registry", () => {
  it("should expose the four finding-level skills with unique ids", () => {
    const skills = getAllSkills();

    expect(skills.map((skill) => skill.id)).toEqual([
      "contextual-fix",
      "triage-decision",
      "systemic-scope",
      "compliance-impact",
    ]);
    expect(new Set(skills.map((skill) => skill.id)).size).toBe(skills.length);
  });

  it("should only offer enabled skills for launch", () => {
    expect(getLaunchableSkills().map((skill) => skill.id)).toEqual([
      "contextual-fix",
      "triage-decision",
      "systemic-scope",
    ]);
    // Compliance Impact ships disabled until MCP exposes a
    // compliance-requirements-per-finding tool and DyR authors its prompt.
    expect(getSkillById("compliance-impact")?.enabled).toBe(false);
  });

  it("should carry the DyR prompt on every launchable skill", () => {
    for (const skill of getLaunchableSkills()) {
      expect(skill.prompt).toContain(
        "The finding under discussion is the one in the UI context block.",
      );
      expect(skill.prompt).toContain("Start by calling load_tools");
    }
  });

  it("should resolve a skill by id and return undefined for unknown ids", () => {
    expect(getSkillById("triage-decision")?.name).toBe("Triage Decision");
    expect(getSkillById("nope")).toBeUndefined();
  });

  it("should chain only triage-decision to contextual-fix", () => {
    expect(getNextSkill("triage-decision")?.id).toBe("contextual-fix");
    expect(getNextSkill("contextual-fix")).toBeUndefined();
    expect(getNextSkill("systemic-scope")).toBeUndefined();
    expect(getNextSkill("compliance-impact")).toBeUndefined();
    for (const skill of getAllSkills()) {
      if (skill.nextSkillId !== null) {
        expect(getSkillById(skill.nextSkillId)).toBeDefined();
      }
    }
  });

  it("should version every skill", () => {
    for (const skill of getAllSkills()) {
      expect(skill.version).toBeGreaterThanOrEqual(1);
    }
  });
});
