// Import skill definitions to trigger registration
import "./definitions/attack-path-custom-query";

// Re-export registry functions and types
export {
  getAllSkillMetadata,
  getRegisteredSkillIds,
  getSkillById,
  registerSkill,
} from "./registry";
export type { SkillDefinition, SkillMetadata } from "./types";
