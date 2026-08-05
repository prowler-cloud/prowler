import { describe, expect, it } from "vitest";

import { getAllSkills, getNextSkill, getSkillById } from "./registry";

describe("skills registry", () => {
  it("should expose the four launch skills with unique ids", () => {
    const skills = getAllSkills();

    expect(skills.map((skill) => skill.id)).toEqual([
      "investigate-blast-radius",
      "verify-exploitability",
      "generate-remediation",
      "triage-draft-ticket",
    ]);
    expect(new Set(skills.map((skill) => skill.id)).size).toBe(skills.length);
  });

  it("should resolve a skill by id and return undefined for unknown ids", () => {
    expect(getSkillById("verify-exploitability")?.name).toBe(
      "Verify exploitability",
    );
    expect(getSkillById("nope")).toBeUndefined();
  });

  it("should chain every nextSkillId to an existing skill", () => {
    for (const skill of getAllSkills()) {
      if (skill.nextSkillId !== null) {
        expect(getSkillById(skill.nextSkillId)).toBeDefined();
      }
    }
    expect(getNextSkill("verify-exploitability")?.id).toBe(
      "generate-remediation",
    );
    expect(getNextSkill("triage-draft-ticket")).toBeUndefined();
  });

  it("should define ordered steps for every skill", () => {
    for (const skill of getAllSkills()) {
      expect(skill.steps.length).toBeGreaterThanOrEqual(3);
      expect(skill.version).toBeGreaterThanOrEqual(1);
    }
  });
});
