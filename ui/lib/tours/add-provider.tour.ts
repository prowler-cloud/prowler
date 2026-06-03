import {
  defineTour,
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
  type TourStepHandlers,
} from "./tour-types";

// The literal targets this tour anchors, as a const map. `defineTour<...>`
// preserves the union so `useDriverTour` can validate `stepHandlers` keys and
// `waitForStep` arguments against exactly these values.
export const ADD_PROVIDER_TOUR_TARGETS = {
  TRIGGER: "trigger",
  PROVIDER_TYPE: "provider-type",
} as const;

export type AddProviderTourTarget =
  (typeof ADD_PROVIDER_TOUR_TARGETS)[keyof typeof ADD_PROVIDER_TOUR_TARGETS];

export const addProviderTour = defineTour<AddProviderTourTarget>({
  id: "add-provider",
  version: 1,
  // Scopes the `tour:check` / `prowler-tour` drift check to the providers tree
  // where the `trigger` and `provider-type` anchors live.
  coversFiles: ["ui/components/providers/**"],
  steps: [
    {
      // Modal welcome step — no `target`, rendered as a centered popover.
      title: "Connect your first provider",
      description:
        "Prowler scans the cloud accounts you connect. Let's walk through adding your first provider so scans have something to assess.",
    },
    {
      target: "trigger",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Open the Add Provider wizard",
      description:
        "Click Add Provider to launch the setup wizard. We'll point out the first thing to choose.",
    },
    {
      target: "provider-type",
      side: TOUR_STEP_SIDES.RIGHT,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Pick a provider type",
      description:
        "Choose the cloud you want to connect (AWS, Azure, GCP, and more). From here the wizard guides you through the rest — go at your own pace.",
    },
  ],
});

// Step handlers are intentionally NOT part of the `TourDefinition` (which is the
// CI-scanned, serializable shape). They are passed to `useDriverTour` at
// consumption time. The factory takes the imperative wizard-open callback the
// providers page owns (finalized in Slice C) so the tour file stays free of
// page-level plumbing. The `trigger` step opens the wizard, then waits for the
// `provider-type` anchor to mount before advancing; `provider-type` is the last
// anchored step and releases control back to the user on completion.
export function createAddProviderTourStepHandlers(openWizard: () => void): {
  [K in AddProviderTourTarget]?: TourStepHandlers<AddProviderTourTarget>;
} {
  return {
    [ADD_PROVIDER_TOUR_TARGETS.TRIGGER]: {
      onNext: async ({ waitForStep }) => {
        openWizard();
        await waitForStep(ADD_PROVIDER_TOUR_TARGETS.PROVIDER_TYPE);
      },
    },
  };
}
