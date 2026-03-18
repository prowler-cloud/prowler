import { registerSkill } from "./registry";
import { customAttackPathQuerySkill } from "./definitions/attack-path-custom-query";

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
