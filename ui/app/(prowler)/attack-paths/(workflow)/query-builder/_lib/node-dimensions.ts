export const RESOURCE_NODE_DIMENSIONS = {
  WIDTH: 136,
  HEIGHT: 124,
  LABEL_MAX_CHARS: 16,
  LABEL_MAX_LINES: 4,
} as const;

export const FINDING_NODE_DIMENSIONS = {
  WIDTH: 150,
  HEIGHT: 124,
  LABEL_MAX_CHARS: 18,
  LABEL_MAX_LINES: 4,
} as const;

export const INTERNET_NODE_DIMENSIONS = {
  DIAMETER: 80,
} as const;

// A collapsed resource-class group: same footprint as a resource node so the
// layout stays even, plus a count badge and an "expand" hint.
export const GROUP_NODE_DIMENSIONS = {
  WIDTH: 136,
  HEIGHT: 124,
  LABEL_MAX_CHARS: 16,
  LABEL_MAX_LINES: 2,
} as const;

// The terminal outcome node (circular, visually distinct endpoint).
export const OUTCOME_NODE_DIMENSIONS = {
  WIDTH: 136,
  HEIGHT: 124,
  LABEL_MAX_CHARS: 16,
  LABEL_MAX_LINES: 2,
} as const;
