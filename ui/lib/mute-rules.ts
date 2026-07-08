export const MAX_MUTE_RULE_NAME_LENGTH = 100;
export const MAX_MUTE_RULE_REASON_LENGTH = 500;

export const MUTE_RULE_NAME_TOO_LONG_MESSAGE = `Name must be ${MAX_MUTE_RULE_NAME_LENGTH} characters or fewer`;
export const MUTE_RULE_REASON_TOO_LONG_MESSAGE = `Reason must be ${MAX_MUTE_RULE_REASON_LENGTH} characters or fewer`;

export function getMuteRuleNameCounterText(name: string): string {
  return `${name.length}/${MAX_MUTE_RULE_NAME_LENGTH} characters`;
}

export function getMuteRuleReasonCounterText(reason: string): string {
  return `${reason.length}/${MAX_MUTE_RULE_REASON_LENGTH} characters`;
}

export function enforceMuteRuleNameLimit(name: string): {
  value: string;
  error?: string;
} {
  if (name.length <= MAX_MUTE_RULE_NAME_LENGTH) {
    return { value: name };
  }

  return {
    value: name.slice(0, MAX_MUTE_RULE_NAME_LENGTH),
    error: MUTE_RULE_NAME_TOO_LONG_MESSAGE,
  };
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
