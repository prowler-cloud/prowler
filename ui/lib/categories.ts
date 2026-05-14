/**
 * Special cases that don't follow standard capitalization rules.
 * Add entries here for edge cases that heuristics can't handle.
 */
const SPECIAL_CASES: Record<string, string> = {
  // Compliance framework acronyms (4+ chars, not caught by length heuristic)
  gdpr: "GDPR",
  hipaa: "HIPAA",
  nist: "NIST",
  mitre: "MITRE",
  fedramp: "FedRAMP",
  ffiec: "FFIEC",
  kisa: "KISA",
  cisa: "CISA",
};

/**
 * Converts a category ID to a human-readable label.
 *
 * Capitalization rules (in order of priority):
 * 1. Special cases dictionary - for edge cases that don't follow patterns
 * 2. Acronym + version pattern (e.g., imdsv1 -> IMDSv1, apiv2 -> APIv2)
 * 3. Short words (≤3 chars) - fully capitalized (e.g., iam -> IAM, ec2 -> EC2)
 * 4. Default - capitalize first letter (e.g., internet -> Internet)
 *
 * Examples:
 * - "internet-exposed" -> "Internet Exposed"
 * - "iam" -> "IAM"
 * - "ec2-imdsv1" -> "EC2 IMDSv1"
 * - "forensics-ready" -> "Forensics Ready"
 */
/**
 * Generic label formatter that works with any delimiter.
 * Use this for formatting IDs into human-readable labels.
 *
 * @param id - The ID to format
 * @param delimiter - The delimiter to split on (default: "-")
 */
export function formatLabel(id: string, delimiter = "-"): string {
  return id
    .split(delimiter)
    .map((word) => formatWord(word))
    .join(" ");
}

/**
 * Converts a category ID to a human-readable label.
 * Convenience wrapper for formatLabel with "-" delimiter.
 */
export function getCategoryLabel(id: string): string {
  return formatLabel(id, "-");
}

/**
 * Converts a resource group ID to a human-readable label.
 * Convenience wrapper for formatLabel with "_" delimiter.
 *
 * Examples:
 * - "ai_ml" -> "AI ML"
 * - "api_gateway" -> "API Gateway"
 * - "iam" -> "IAM"
 */
export function getGroupLabel(id: string): string {
  return formatLabel(id, "_");
}

export function formatWord(word: string): string {
  const lowerWord = word.toLowerCase();

  // 1. Check special cases dictionary
  if (lowerWord in SPECIAL_CASES) {
    return SPECIAL_CASES[lowerWord];
  }

  // 2. Acronym + version pattern (e.g., imdsv1 -> IMDSv1)
  const versionMatch = lowerWord.match(/^([a-z]+)(v\d+)$/);
  if (versionMatch) {
    const [, acronym, version] = versionMatch;
    return acronym.toUpperCase() + version.toLowerCase();
  }

  // 3. Short words are likely acronyms (IAM, EC2, S3, API, VPC, etc.)
  if (word.length <= 3) {
    return word.toUpperCase();
  }

  // 4. Default: capitalize first letter
  return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
}
