import { customAttackPathQuerySkill } from "./definitions/attack-path-custom-query";
import { registerSkill } from "./registry";

// Explicit registration — tree-shake-proof
registerSkill(customAttackPathQuerySkill);

// Re-export registry functions and types
export {
  getAllSkillMetadata,
  getRegisteredSkillIds,
  getSkillById,
  registerSkill,
} from "./registry";
export type { SkillDefinition, SkillMetadata } from "./types";
