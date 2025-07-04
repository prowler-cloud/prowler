import yaml from "js-yaml";

import { mutedFindingsConfigFormSchema } from "@/types/formSchemas";

// ========================
// YAML Validation Functions
// ========================

/**
 * Validates if a string is valid YAML and returns a non-array object
 */
export const isValidYaml = (val: string): boolean => {
  try {
    const parsed = yaml.load(val);

    if (parsed === null || parsed === undefined) {
      return false;
    }

    if (typeof parsed !== "object" || Array.isArray(parsed)) {
      return false;
    }

    return true;
  } catch (error) {
    return false;
  }
};

/**
 * Validates if a YAML string contains a valid mutelist structure
 */
export const isValidMutelistYaml = (val: string): boolean => {
  try {
    const parsed = yaml.load(val) as Record<string, any>;

    // yaml.load() can return null, arrays, or primitives
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return false;
    }

    // Verify structure using optional chaining
    const accounts = parsed.Mutelist?.Accounts;
    if (!accounts || typeof accounts !== "object" || Array.isArray(accounts)) {
      return false;
    }

    const accountKeys = Object.keys(accounts);
    if (accountKeys.length === 0) return false;

    for (const accountKey of accountKeys) {
      const account = accounts[accountKey];
      if (!account || typeof account !== "object" || Array.isArray(account)) {
        return false;
      }

      const checks = account.Checks;
      if (!checks || typeof checks !== "object" || Array.isArray(checks)) {
        return false;
      }

      const checkKeys = Object.keys(checks);
      if (checkKeys.length === 0) return false;

      for (const checkKey of checkKeys) {
        const check = checks[checkKey];
        if (!check || typeof check !== "object" || Array.isArray(check)) {
          return false;
        }

        const { Regions: regions, Resources: resources } = check;
        if (!Array.isArray(regions) || !Array.isArray(resources)) {
          return false;
        }
      }
    }

    return true;
  } catch (error) {
    return false;
  }
};

/**
 * Validates YAML using the mutelist schema and returns detailed error information
 */
export const parseYamlValidation = (
  yamlString: string,
): { isValid: boolean; error?: string } => {
  try {
    const result = mutedFindingsConfigFormSchema.safeParse({
      configuration: yamlString,
    });

    if (result.success) {
      return { isValid: true };
    } else {
      const firstError = result.error.issues[0];
      return {
        isValid: false,
        error: firstError.message,
      };
    }
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Unknown validation error";
    return { isValid: false, error: errorMessage };
  }
};

// ========================
// YAML Conversion Functions
// ========================

/**
 * Converts a configuration (string or object) to YAML format
 */
export const convertToYaml = (config: string | object): string => {
  if (!config) return "";

  try {
    // If it's already an object, convert directly to YAML
    if (typeof config === "object") {
      return yaml.dump(config, { indent: 2 });
    }

    // If it's a string, try to parse as JSON first
    try {
      const jsonConfig = JSON.parse(config);
      return yaml.dump(jsonConfig, { indent: 2 });
    } catch {
      // If it's not JSON, assume it's already YAML
      return config;
    }
  } catch (error) {
    console.error("Error converting config to YAML:", error);
    return config.toString();
  }
};
