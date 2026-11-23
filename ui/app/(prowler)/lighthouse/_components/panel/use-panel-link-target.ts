"use client";

import { selectHasModalHost, useSidePanelStore } from "@/store/side-panel";

const NEW_TAB_LINK_PROPS = {
  target: "_blank",
  rel: "noopener noreferrer",
} as const;

// While a dialog shares the screen with the panel, panel links open in a new
// tab so following one never navigates that dialog away.
export function usePanelLinkTarget() {
  const hasModalHost = useSidePanelStore(selectHasModalHost);
  return hasModalHost ? NEW_TAB_LINK_PROPS : {};
}
