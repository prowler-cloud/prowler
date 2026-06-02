// Inputs the checkpoint watcher reads to decide whether to open the dialog.
// Framework-free so the firing rule is unit-testable without React effects.
export interface CheckpointInput {
  // The previous `hasProviders` value. `undefined` means "first read, no
  // transition observed yet".
  prev: boolean | undefined;
  // The current `hasProviders` value.
  next: boolean;
  // Whether the checkpoint was already handled (continue/finish chosen) in this
  // browser, per the localStorage marker.
  handled: boolean;
}

// Fires the checkpoint EXACTLY on a concrete `false -> true` flip that has not
// been handled. The `undefined -> true` case (user already had providers) must
// NOT fire — only a real first-connect transition counts.
export function shouldFireCheckpoint({
  prev,
  next,
  handled,
}: CheckpointInput): boolean {
  return prev === false && next === true && !handled;
}
