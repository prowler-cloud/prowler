// Inputs the checkpoint watcher reads to decide whether the genuine
// first-provider transition occurred. Framework-free so the rule is
// unit-testable without React effects.
export interface CheckpointArmingInput {
  // The previous `hasProviders` value. `undefined` means "first read, no
  // transition observed yet".
  prev: boolean | undefined;
  // The current `hasProviders` value.
  next: boolean;
  // Whether the checkpoint was already handled (continue/finish chosen) in this
  // browser, per the localStorage marker.
  handled: boolean;
}

// Full input for the firing decision: arming plus the provider-wizard open
// signal. The provider wizard creates the provider record on its FIRST step, so
// `hasProviders` can flip `true` MID-WIZARD; the checkpoint must wait until the
// wizard closes before opening its own dialog (two Radix dialogs cannot coexist
// without closing the wizard).
export interface CheckpointInput extends CheckpointArmingInput {
  // Whether the provider wizard is currently open. While `true`, the checkpoint
  // must not fire even on a genuine flip.
  wizardOpen: boolean;
}

// True on a concrete `false -> true` flip that has not been handled. The
// `undefined -> true` case (user already had providers) must NOT arm — only a
// real first-connect transition counts. Independent of the wizard so the
// watcher can latch "armed" the moment the flip happens and fire later.
export function isCheckpointArmed({
  prev,
  next,
  handled,
}: CheckpointArmingInput): boolean {
  return prev === false && next === true && !handled;
}

// Fires the checkpoint EXACTLY when a genuine first-connect transition has been
// observed AND the provider wizard is closed. Deferring while the wizard is
// open prevents the dialog from interrupting the Add Provider flow.
export function shouldFireCheckpoint(input: CheckpointInput): boolean {
  return isCheckpointArmed(input) && !input.wizardOpen;
}
