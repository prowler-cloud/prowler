import { toLocalDateString } from "@/lib/date-utils";

const POSTURE_CHANGE_DEFAULT_DAYS = 30;
// Mirrors the API cap so the modal rejects what the API would 400.
export const POSTURE_CHANGE_MAX_DAYS = 366;

const DAY_MS = 24 * 60 * 60 * 1000;

export interface PostureChangePeriod {
  from?: Date;
  to?: Date;
}

/** The current UTC calendar day as a local date, since the API reads periods in UTC. */
export const utcToday = (now: Date): Date =>
  new Date(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());

export const defaultPostureChangePeriod = (
  today: Date,
): PostureChangePeriod => ({
  from: new Date(today.getTime() - (POSTURE_CHANGE_DEFAULT_DAYS - 1) * DAY_MS),
  to: today,
});

const startOfDay = (date: Date) =>
  new Date(date.getFullYear(), date.getMonth(), date.getDate());

/** Returns the API dates, or the reason the period cannot be requested. */
export const validatePostureChangePeriod = (
  period: PostureChangePeriod | undefined,
  today: Date,
): { dateFrom: string; dateTo: string } | { error: string } => {
  if (!period?.from || !period.to) {
    return { error: "Select a start and an end date." };
  }
  const from = startOfDay(period.from);
  const to = startOfDay(period.to);
  if (to > startOfDay(today)) {
    return { error: "The end date cannot be in the future." };
  }
  const days = Math.round((to.getTime() - from.getTime()) / DAY_MS) + 1;
  if (days > POSTURE_CHANGE_MAX_DAYS) {
    return {
      error: `The period cannot exceed ${POSTURE_CHANGE_MAX_DAYS} days.`,
    };
  }
  return {
    dateFrom: toLocalDateString(from) ?? "",
    dateTo: toLocalDateString(to) ?? "",
  };
};

export const POSTURE_CHANGE_LANGUAGE = {
  EN: "en",
  ES: "es",
} as const;

export type PostureChangeLanguage =
  (typeof POSTURE_CHANGE_LANGUAGE)[keyof typeof POSTURE_CHANGE_LANGUAGE];

export const POSTURE_CHANGE_LANGUAGE_LABELS: Record<
  PostureChangeLanguage,
  string
> = {
  [POSTURE_CHANGE_LANGUAGE.EN]: "English",
  [POSTURE_CHANGE_LANGUAGE.ES]: "Español",
};
