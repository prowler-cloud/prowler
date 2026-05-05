export const MAX_MUTE_RULE_REASON_LENGTH = 500;

export const MUTE_RULE_REASON_TOO_LONG_MESSAGE = `Reason must be ${MAX_MUTE_RULE_REASON_LENGTH} characters or fewer`;

export function getMuteRuleReasonCounterText(reason: string): string {
  return `${reason.length}/${MAX_MUTE_RULE_REASON_LENGTH} characters`;
}

export function enforceMuteRuleReasonLimit(reason: string): {
  value: string;
  error?: string;
} {
  if (reason.length <= MAX_MUTE_RULE_REASON_LENGTH) {
    return { value: reason };
  }

  return {
    value: reason.slice(0, MAX_MUTE_RULE_REASON_LENGTH),
    error: MUTE_RULE_REASON_TOO_LONG_MESSAGE,
  };
}
