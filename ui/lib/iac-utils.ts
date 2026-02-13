/**
 * Extracts line range from a Finding UID
 * Finding UID format: {CheckID}-{resource_name}-{line_range}
 * Example: "AVD-AWS-0001-main.tf-10:15" -> "10:15"
 *
 * @param findingUid - The finding UID
 * @returns Line range string or null if not found
 */
export function extractLineRangeFromUid(findingUid: string): string | null {
  if (!findingUid) {
    return null;
  }

  // Split by dash and get the last part (line range)
  const parts = findingUid.split("-");
  const lastPart = parts[parts.length - 1];

  // Check if the last part is a line range in format "number:number"
  // This ensures we don't confuse numeric filenames with line ranges
  if (/^\d+:\d+$/.test(lastPart)) {
    return lastPart;
  }

  return null;
}

/**
 * Builds a Git repository URL with file path and line numbers
 * Supports GitHub, GitLab, Bitbucket, and generic Git URLs
 *
 * @param repoUrl - Repository URL (can be HTTPS or git@ format)
 * @param filePath - Path to the file in the repository
 * @param lineRange - Line range in format "10-15" or "10:15" or "10"
 * @param branch - Git branch name (defaults to "main" if not provided)
 * @returns Complete URL to the file with line numbers, or null if URL cannot be built
 */
export function buildGitFileUrl(
  repoUrl: string,
  filePath: string,
  lineRange: string,
  branch?: string,
): string | null {
  if (!repoUrl || !filePath) {
    return null;
  }

  try {
    // Normalize the repository URL
    let normalizedUrl = repoUrl.trim();

    // Convert git@ format to HTTPS (best effort)
    if (normalizedUrl.startsWith("git@")) {
      // git@github.com:user/repo.git -> https://github.com/user/repo
      normalizedUrl = normalizedUrl
        .replace(/^git@/, "https://")
        .replace(/\.git$/, "")
        .replace(/:([^:]+)$/, "/$1"); // Replace last : with /
    }

    // Remove .git suffix if present
    normalizedUrl = normalizedUrl.replace(/\.git$/, "");

    // Parse URL to determine provider
    const url = new URL(normalizedUrl);
    const hostname = url.hostname.toLowerCase();

    // Clean up file path (remove leading slashes)
    const cleanFilePath = filePath.replace(/^\/+/, "");

    // Parse line range
    const { startLine, endLine } = parseLineRange(lineRange);

    // Build URL based on Git provider
    if (hostname.includes("github")) {
      return buildGitHubUrl(
        normalizedUrl,
        cleanFilePath,
        startLine,
        endLine,
        branch,
      );
    } else if (hostname.includes("gitlab")) {
      return buildGitLabUrl(
        normalizedUrl,
        cleanFilePath,
        startLine,
        endLine,
        branch,
      );
    } else if (hostname.includes("bitbucket")) {
      return buildBitbucketUrl(
        normalizedUrl,
        cleanFilePath,
        startLine,
        endLine,
        branch,
      );
    } else {
      // Generic Git provider - try GitHub format as fallback
      return buildGitHubUrl(
        normalizedUrl,
        cleanFilePath,
        startLine,
        endLine,
        branch,
      );
    }
  } catch (error) {
    console.error("Error building Git file URL:", error);
    return null;
  }
}

/**
 * Parses line range string into start and end line numbers
 */
function parseLineRange(lineRange: string): {
  startLine: number | null;
  endLine: number | null;
} {
  if (!lineRange || lineRange === "file") {
    return { startLine: null, endLine: null };
  }

  // Handle formats: "10-15", "10:15", "10"
  // Safe regex: anchored pattern for line numbers only (no ReDoS risk)

  const match = lineRange.match(/^(\d+)[-:]?(\d+)?$/);
  if (match) {
    const startLine = parseInt(match[1], 10);
    const endLine = match[2] ? parseInt(match[2], 10) : startLine;
    return { startLine, endLine };
  }

  return { startLine: null, endLine: null };
}

/**
 * Builds GitHub-style URL
 * Format: https://github.com/user/repo/blob/{branch}/path/file.tf#L10-L15
 */
function buildGitHubUrl(
  baseUrl: string,
  filePath: string,
  startLine: number | null,
  endLine: number | null,
  branch?: string,
): string {
  // Use provided branch, default to "main" if not provided
  const branchName = branch || "main";
  let url = `${baseUrl}/blob/${branchName}/${filePath}`;

  if (startLine !== null) {
    if (endLine !== null && endLine !== startLine) {
      url += `#L${startLine}-L${endLine}`;
    } else {
      url += `#L${startLine}`;
    }
  }

  return url;
}

/**
 * Builds GitLab-style URL
 * Format: https://gitlab.com/user/repo/-/blob/{branch}/path/file.tf#L10-15
 */
function buildGitLabUrl(
  baseUrl: string,
  filePath: string,
  startLine: number | null,
  endLine: number | null,
  branch?: string,
): string {
  const branchName = branch || "main";
  let url = `${baseUrl}/-/blob/${branchName}/${filePath}`;

  if (startLine !== null) {
    if (endLine !== null && endLine !== startLine) {
      url += `#L${startLine}-${endLine}`;
    } else {
      url += `#L${startLine}`;
    }
  }

  return url;
}

/**
 * Builds Bitbucket-style URL
 * Format: https://bitbucket.org/user/repo/src/{branch}/path/file.tf#lines-10:15
 */
function buildBitbucketUrl(
  baseUrl: string,
  filePath: string,
  startLine: number | null,
  endLine: number | null,
  branch?: string,
): string {
  const branchName = branch || "main";
  let url = `${baseUrl}/src/${branchName}/${filePath}`;

  if (startLine !== null) {
    if (endLine !== null && endLine !== startLine) {
      url += `#lines-${startLine}:${endLine}`;
    } else {
      url += `#lines-${startLine}`;
    }
  }

  return url;
}
