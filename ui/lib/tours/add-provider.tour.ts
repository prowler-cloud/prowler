import {
  defineTour,
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
  type TourStepHandlers,
} from "./tour-types";

// Const map keeps the union narrow so `useDriverTour` can validate step keys.
export const ADD_PROVIDER_TOUR_TARGETS = {
  TRIGGER: "trigger",
  PROVIDER_TYPE: "provider-type",
} as const;

export type AddProviderTourTarget =
  (typeof ADD_PROVIDER_TOUR_TARGETS)[keyof typeof ADD_PROVIDER_TOUR_TARGETS];

export const addProviderTour = defineTour<AddProviderTourTarget>({
  id: "add-provider",
  version: 1,
  coversFiles: ["ui/components/providers/**"],
  steps: [
    {
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

// Step handlers are passed to `useDriverTour` at consumption time (not part of `TourDefinition`).
// `trigger` opens the wizard and waits for `provider-type` to mount before advancing.
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
