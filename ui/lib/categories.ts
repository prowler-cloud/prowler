/**
 * Special cases that don't follow standard capitalization rules.
 * Add entries here for edge cases that heuristics can't handle.
 */
const SPECIAL_CASES: Record<string, string> = {
  // Add special cases here if needed, e.g.:
  // "someweirdcase": "SomeWeirdCase",
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
export function getCategoryLabel(id: string): string {
  return id
    .split("-")
    .map((word) => formatWord(word))
    .join(" ");
}

function formatWord(word: string): string {
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
