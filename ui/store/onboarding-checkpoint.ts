import { create } from "zustand";

// localStorage flag set once the user has either continued or finished the
// checkpoint. It keeps the dialog from re-appearing on any later provider
// connection in this browser. Distinct from per-tour `prowler.tour.*`
// completion records.
export const CHECKPOINT_MARKER = "prowler.onboarding.checkpoint";

function isCheckpointHandled(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.localStorage.getItem(CHECKPOINT_MARKER) !== null;
  } catch {
    // Fail open: an unreadable storage should not block the checkpoint.
    return false;
  }
}

interface OnboardingCheckpointState {
  // True once the user accepted the welcome modal ("Get started"), meaning they
  // are actively going through onboarding. Only an armed checkpoint may open —
  // this is what keeps an established user (who later adds another provider)
  // from ever seeing the dialog.
  armed: boolean;
  // Whether the checkpoint dialog should be shown.
  open: boolean;

  // Mark the checkpoint as armed. Called by the gate's "Get started" accept.
  // Skip/dismiss must NOT call this.
  arm: () => void;
  // Requested by the provider wizard when it closes. Opens the checkpoint only
  // when it is armed, a provider was actually connected during the wizard, and
  // the checkpoint has not already been handled in this browser.
  requestOpenOnWizardClose: (input: { providerConnected: boolean }) => void;
  // Close the dialog and disarm. The handled marker (continue/finish) is owned
  // by the watcher; this only resets the ephemeral open/armed state.
  close: () => void;
}

// Ephemeral, NOT persisted: arming and open state are per-session signals tied
// to the live onboarding flow. Durable "already saw this" memory stays in the
// `CHECKPOINT_MARKER` localStorage flag (read here, written by the watcher), so
// a refresh never resurrects the dialog.
export const useOnboardingCheckpointStore = create<OnboardingCheckpointState>(
  (set) => ({
    armed: false,
    open: false,

    arm: () => set({ armed: true }),

    requestOpenOnWizardClose: ({ providerConnected }) =>
      set((state) => {
        if (state.armed && providerConnected && !isCheckpointHandled()) {
          return { open: true };
        }
        return {};
      }),

    close: () => set({ open: false, armed: false }),
  }),
);
