import {
  defineTour,
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
} from "./tour-types";

// The literal target this tour anchors. `defineTour<...>` preserves the union
// so `useDriverTour` can validate `waitForStep` arguments against exactly this
// value. The tour deliberately stops at the Add Provider button: it must NOT
// anchor inside the provider wizard, because driver.js renders a full-screen
// overlay that the wizard's Radix `Dialog` treats as a click-outside and would
// close the wizard mid-flow.
export type AddProviderTourTarget = "trigger";

export const addProviderTour = defineTour<AddProviderTourTarget>({
  id: "add-provider",
  version: 1,
  // Scopes the `tour:check` / `prowler-tour` drift check to the providers tree
  // where the `trigger` anchor lives.
  coversFiles: ["ui/components/providers/**"],
  steps: [
    {
      // Modal welcome step — no `target`, rendered as a centered popover.
      title: "Connect your first provider",
      description:
        "Prowler scans the cloud accounts you connect. Let's walk through adding your first provider so scans have something to assess.",
    },
    {
      // Final step — highlights the Add Provider button and hands control back
      // to the user. Clicking the button opens the wizard on its own surface;
      // the tour does not follow the user into the dialog.
      target: "trigger",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Connect your first provider",
      description:
        "Click Add Provider to open the setup wizard — it will guide you through the rest.",
    },
  ],
});
