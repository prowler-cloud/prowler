import { create } from "zustand";

// Persisted flag that prevents the checkpoint dialog from re-appearing after it has been handled.
export const CHECKPOINT_MARKER = "prowler.onboarding.checkpoint";

function isCheckpointHandled(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.localStorage.getItem(CHECKPOINT_MARKER) !== null;
  } catch {
    // Fail open: unreadable storage should not block the checkpoint.
    return false;
  }
}

interface OnboardingCheckpointState {
  // armed: set by the gate's "Get started"; prevents established users from seeing the dialog.
  armed: boolean;
  open: boolean;

  arm: () => void;
  // Opens the checkpoint only when armed, a provider was connected, and the marker is unset.
  requestOpenOnWizardClose: (input: { providerConnected: boolean }) => void;
  // Resets ephemeral open/armed state; the durable marker is managed by the watcher.
  close: () => void;
}

// Ephemeral, NOT persisted: durable "already saw this" memory stays in CHECKPOINT_MARKER.
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
