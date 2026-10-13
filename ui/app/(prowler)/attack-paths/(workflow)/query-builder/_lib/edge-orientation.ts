/**
 * Shared edge-direction normalization.
 *
 * Container relationships (e.g. a resource RUNS_IN a VPC) arrive as
 * `child -> container`, but the attack path reads best as `container -> child`.
 * The Dagre layout reverses them for hierarchy, so any code that reasons about
 * flow direction *before* layout — ranking, grouping, sink detection for the
 * terminal outcome node — must apply the same reversal or it will disagree with
 * what the user finally sees (the outcome node lands mid-path instead of at the
 * end). Keeping the rule here lets the layout and the view transform share it.
 */

// Container relationships that get reversed for proper hierarchy.
const CONTAINER_RELATIONS = new Set([
  "RUNS_IN",
  "BELONGS_TO",
  "LOCATED_IN",
  "PART_OF",
]);

/**
 * Returns the [source, target] an edge should use once laid out. Container
 * relationships are reversed; every other edge keeps its original direction.
 */
export const orientEdgeForLayout = (
  source: string,
  target: string,
  type: string,
): [string, string] =>
  CONTAINER_RELATIONS.has(type) ? [target, source] : [source, target];
