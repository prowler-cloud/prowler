/**
 * Tells whether the browser is already showing a flow's route.
 *
 * A flow route may pin query params (`/compliance?tab=per-scan`,
 * `/scans?tab=active`) that select the view its anchors live in, so a plain
 * string compare against `pathname` never matches and the replay degrades into
 * a full navigation — losing whatever params the user had built up.
 *
 * The pinned params are a subset check, not an equality one: extra params the
 * user picked up (a selected scan, filters) still count as being on the route.
 */
export function isOnFlowRoute(
  flowRoute: string,
  pathname: string,
  searchParams: URLSearchParams,
): boolean {
  const [routePath, routeQuery = ""] = flowRoute.split("?");

  if (routePath !== pathname) {
    return false;
  }

  // forEach, not for..of: URLSearchParams is only iterable under
  // downlevelIteration, which this tsconfig does not enable.
  let carriesPinnedParams = true;
  new URLSearchParams(routeQuery).forEach((value, key) => {
    if (searchParams.get(key) !== value) {
      carriesPinnedParams = false;
    }
  });

  return carriesPinnedParams;
}
