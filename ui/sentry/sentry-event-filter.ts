import { applySentryEventPolicy } from "./event-policy";

// Backward-compatible export name: the implementation now applies the full
// actionability policy, including warning drops and expected API noise filters.
export function filterWarningSentryEvent<TEvent extends object>(event: TEvent) {
  return applySentryEventPolicy(event);
}
