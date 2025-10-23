/**
 * Tabs component color constants
 */
export const TABS_COLORS = {
  separator: {
    light: "#E9E9F0",
    dark: "#171D30",
  },
  underline: {
    active: "#20B853",
  },
} as const;

/**
 * Tabs component base styles
 */
export const TABS_STYLES = {
  root: "w-full",
  list: `inline-flex w-full items-center border-[${TABS_COLORS.separator.light}] dark:border-[${TABS_COLORS.separator.dark}]`,
  trigger: {
    base: "relative inline-flex items-center justify-center gap-2 px-4 py-3 text-sm font-medium transition-colors disabled:pointer-events-none disabled:opacity-50",
    border: `border-r border-[${TABS_COLORS.separator.light}] last:border-r-0 dark:border-[${TABS_COLORS.separator.dark}]`,
    text: "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white",
    active:
      "data-[state=active]:text-slate-900 dark:data-[state=active]:text-white",
    underline: `after:absolute after:bottom-0 after:left-1/2 after:h-0.5 after:w-0 after:-translate-x-1/2 after:bg-[${TABS_COLORS.underline.active}] after:transition-all data-[state=active]:after:w-[calc(100%-theme(spacing.5))]`,
    focus: `focus-visible:ring-2 focus-visible:ring-[${TABS_COLORS.underline.active}] focus-visible:ring-offset-2 focus-visible:ring-offset-white focus-visible:outline-none dark:focus-visible:ring-offset-slate-950`,
    icon: "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  },
  content:
    "mt-2 focus-visible:rounded-md focus-visible:outline-1 focus-visible:ring-[3px] focus-visible:border-ring focus-visible:outline-ring focus-visible:ring-ring/50",
} as const;

/**
 * Build trigger className by combining style parts
 */
export function buildTriggerClassName(): string {
  return [
    TABS_STYLES.trigger.base,
    TABS_STYLES.trigger.border,
    TABS_STYLES.trigger.text,
    TABS_STYLES.trigger.active,
    TABS_STYLES.trigger.underline,
    TABS_STYLES.trigger.focus,
    TABS_STYLES.trigger.icon,
  ].join(" ");
}

/**
 * Build list className
 */
export function buildListClassName(): string {
  return `inline-flex w-full items-center border-[${TABS_COLORS.separator.light}] dark:border-[${TABS_COLORS.separator.dark}]`;
}
