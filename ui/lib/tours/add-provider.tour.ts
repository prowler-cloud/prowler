import {
  defineTour,
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
} from "./tour-types";

// Const map keeps the union narrow so `useDriverTour` can validate step keys.
export const ADD_PROVIDER_TOUR_TARGETS = {
  TRIGGER: "trigger",
  PROVIDER_TYPE: "provider-type",
  // Wraps the whole wizard modal so the final step's spotlight covers every input
  // (UID, alias) and the footer — driver.js only keeps the highlighted element and
  // its descendants interactive, so anchoring here stops the overlay from freezing
  // those inputs.
  WIZARD_BODY: "wizard-body",
} as const;

export type AddProviderTourTarget =
  (typeof ADD_PROVIDER_TOUR_TARGETS)[keyof typeof ADD_PROVIDER_TOUR_TARGETS];

export const addProviderTour = defineTour<AddProviderTourTarget>({
  id: "add-provider",
  // v2: the tour now drives the user into the wizard body (provider-type + wizard-body
  // steps) instead of ending at type selection.
  version: 2,
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
      // No Next button: clicking the highlighted "Add a Provider" button opens the
      // wizard and advances the tour (see openProviderWizard).
      autoAdvance: true,
      title: "Open the Add Provider wizard",
      description:
        "Click Add a Provider to open the setup wizard. We'll point out the first thing to choose.",
    },
    {
      target: "provider-type",
      side: TOUR_STEP_SIDES.RIGHT,
      align: TOUR_STEP_ALIGNMENTS.START,
      // No Next button: the wizard advances the tour when a type is picked.
      autoAdvance: true,
      title: "Pick a provider type",
      description:
        "Choose the cloud you want to connect (AWS, Azure, GCP, and more). Selecting one takes you to the account details.",
    },
    {
      target: "wizard-body",
      // Pinned to the left of the form column, mirroring the provider-type step.
      side: TOUR_STEP_SIDES.LEFT,
      align: TOUR_STEP_ALIGNMENTS.START,
      // Final step: stays until the user closes it or advances to credentials, which
      // the wizard ends the tour from. No Next button.
      autoAdvance: true,
      title: "Add your account details",
      description:
        "Enter your account ID and an optional alias, then continue. From here you'll add credentials, test the connection, and launch your first scan — at your own pace.",
    },
  ],
});
