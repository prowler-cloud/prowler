import "server-only";

import { tool } from "@langchain/core/tools";
import { addBreadcrumb } from "@sentry/nextjs";
import { z } from "zod";

import {
  getRegisteredSkillIds,
  getSkillById,
} from "@/lib/lighthouse/skills/index";

interface SkillLoadedResult {
  found: true;
  skillId: string;
  name: string;
  instructions: string;
}

interface SkillNotFoundResult {
  found: false;
  skillId: string;
  message: string;
  availableSkills: string[];
}

type LoadSkillResult = SkillLoadedResult | SkillNotFoundResult;

export const loadSkill = tool(
  async ({ skillId }: { skillId: string }): Promise<LoadSkillResult> => {
    addBreadcrumb({
      category: "skill",
      message: `load_skill called for: ${skillId}`,
      level: "info",
      data: { skillId },
    });

    const skill = getSkillById(skillId);

    if (!skill) {
      const availableSkills = getRegisteredSkillIds();

      addBreadcrumb({
        category: "skill",
        message: `Skill not found: ${skillId}`,
        level: "warning",
        data: { skillId, availableSkills },
      });

      return {
        found: false,
        skillId,
        message: `Skill '${skillId}' not found.`,
        availableSkills,
      };
    }

    return {
      found: true,
      skillId: skill.metadata.id,
      name: skill.metadata.name,
      instructions: skill.instructions,
    };
  },
  {
    name: "load_skill",
    description: `Load detailed instructions for a specialized skill.

Skills provide domain-specific guidance, workflows, and schema knowledge for complex tasks.
Use this when you identify a relevant skill from the skill catalog in your system prompt.

Returns:
- Skill metadata (id, name)
- Full skill instructions with workflows and examples`,
    schema: z.object({
      skillId: z
        .string()
        .describe(
          "The ID of the skill to load (from the skill catalog in your system prompt)",
        ),
    }),
  },
);
