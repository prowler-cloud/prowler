import { DEFAULT_REALTIME_POLICY } from "@/lib/realtime/policy-schema";
import {
  REALTIME_MODE,
  REALTIME_SETUP_STEP,
  type RealtimePolicyInput,
  type RealtimeSetupPayload,
  type RealtimeSetupStepId,
} from "@/types/realtime";

/** The wizard's own first step: choosing the account is not stored by the API. */
export const SETUP_ACCOUNT_STEP = "account";

export const SETUP_STEP = {
  ACCOUNT: SETUP_ACCOUNT_STEP,
  ...REALTIME_SETUP_STEP,
} as const;
export type SetupStep = (typeof SETUP_STEP)[keyof typeof SETUP_STEP];

export const SETUP_STEP_ORDER: readonly SetupStep[] = [
  SETUP_STEP.ACCOUNT,
  SETUP_STEP.FEED,
  SETUP_STEP.ENFORCEMENT,
  SETUP_STEP.REMEDIATION,
  SETUP_STEP.ALERTS,
  SETUP_STEP.COST,
  SETUP_STEP.ACTIVATE,
];

export const SETUP_STEP_LABELS: Record<SetupStep, string> = {
  [SETUP_STEP.ACCOUNT]: "Account",
  [SETUP_STEP.FEED]: "Event feed",
  [SETUP_STEP.ENFORCEMENT]: "What to enforce",
  [SETUP_STEP.REMEDIATION]: "Remediation permission",
  [SETUP_STEP.ALERTS]: "Alerts",
  [SETUP_STEP.COST]: "Cost anomalies",
  [SETUP_STEP.ACTIVATE]: "Review and activate",
};

const isRequired = (setup: RealtimeSetupPayload, id: RealtimeSetupStepId) =>
  setup.steps.find((step) => step.id === id)?.required ?? false;

const isDone = (setup: RealtimeSetupPayload, id: RealtimeSetupStepId) =>
  setup.steps.find((step) => step.id === id)?.done ?? false;

/**
 * Where the wizard picks up: the first required step that is not done, as the
 * API says. Null once the account is activated (nothing left to set up).
 */
export const resumeStep = (setup: RealtimeSetupPayload): SetupStep | null => {
  if (setup.activated) return null;
  if (setup.next_step) return setup.next_step;
  const open = SETUP_STEP_ORDER.find(
    (id): id is RealtimeSetupStepId =>
      id !== SETUP_STEP.ACCOUNT && isRequired(setup, id) && !isDone(setup, id),
  );
  return open ?? SETUP_STEP.ACTIVATE;
};

/**
 * A step can be opened once every required step before it is done, so the
 * optional ones never block, and the review is never reached with a gap.
 */
export const canEnterStep = (
  step: SetupStep,
  setup: RealtimeSetupPayload | undefined,
): boolean => {
  const index = SETUP_STEP_ORDER.indexOf(step);
  if (index <= 1) return true;
  if (!setup) return false;
  return SETUP_STEP_ORDER.slice(1, index).every(
    (id) =>
      id === SETUP_STEP.ACCOUNT ||
      !isRequired(setup, id as RealtimeSetupStepId) ||
      isDone(setup, id as RealtimeSetupStepId),
  );
};

export const stepProgress = (
  step: SetupStep,
  setup: RealtimeSetupPayload | undefined,
): { required: boolean; done: boolean; detail: string | null } => {
  if (step === SETUP_STEP.ACCOUNT) {
    return { required: true, done: true, detail: null };
  }
  const found = setup?.steps.find((item) => item.id === step);
  return {
    required: found?.required ?? false,
    done: found?.done ?? false,
    detail: found?.detail ?? null,
  };
};

export const nextStepAfter = (step: SetupStep): SetupStep | null =>
  SETUP_STEP_ORDER[SETUP_STEP_ORDER.indexOf(step) + 1] ?? null;

export const stepBefore = (step: SetupStep): SetupStep | null =>
  SETUP_STEP_ORDER[SETUP_STEP_ORDER.indexOf(step) - 1] ?? null;

export const isSetupStep = (value: unknown): value is SetupStep =>
  SETUP_STEP_ORDER.includes(value as SetupStep);

/**
 * What a policy starts as in the wizard: switched off, watching only, dry run
 * on. Nothing is switched on until the last step.
 */
export const WIZARD_DEFAULT_POLICY: RealtimePolicyInput = {
  ...DEFAULT_REALTIME_POLICY,
  enabled: false,
  mode: REALTIME_MODE.MONITOR,
  dry_run: true,
};
