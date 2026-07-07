// Global side panel geometry. The panel width is user-resizable and applied
// as an inline style; MainLayout pushes <main> by exactly the same number of
// pixels so the panel never covers the page. Below the `sm` breakpoint the
// panel is a full-width overlay instead, where pushing would leave no page.
export const SIDE_PANEL_MIN_WIDTH = 360;
export const SIDE_PANEL_MAX_WIDTH = 960;
export const SIDE_PANEL_DEFAULT_WIDTH = 480;
// Detail (finding/resource) content needs drawer-like room, so registering a
// detail view widens the panel to at least this.
export const SIDE_PANEL_DETAIL_MIN_WIDTH = 720;

// Media query matching the breakpoint where the panel switches from
// full-width overlay to fixed-width push panel (Tailwind `sm`).
export const SIDE_PANEL_PUSH_MEDIA_QUERY = "(min-width: 640px)";

export function clampSidePanelWidth(width: number): number {
  const viewportCap =
    typeof window === "undefined"
      ? SIDE_PANEL_MAX_WIDTH
      : Math.floor(window.innerWidth * 0.85);
  return Math.min(
    Math.max(width, SIDE_PANEL_MIN_WIDTH),
    Math.min(SIDE_PANEL_MAX_WIDTH, viewportCap),
  );
}
