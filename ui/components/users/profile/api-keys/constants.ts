export const API_KEY_COLUMN_KEYS = {
  NAME: "name",
  PREFIX: "prefix",
  CREATED: "created",
  LAST_USED: "last_used",
  EXPIRES: "expires",
  STATUS: "status",
  ACTIONS: "actions",
} as const;

export const API_KEY_COLUMNS = [
  { key: API_KEY_COLUMN_KEYS.NAME, label: "NAME" },
  { key: API_KEY_COLUMN_KEYS.PREFIX, label: "PREFIX" },
  { key: API_KEY_COLUMN_KEYS.CREATED, label: "CREATED" },
  { key: API_KEY_COLUMN_KEYS.LAST_USED, label: "LAST USED" },
  { key: API_KEY_COLUMN_KEYS.EXPIRES, label: "EXPIRES" },
  { key: API_KEY_COLUMN_KEYS.STATUS, label: "STATUS" },
  { key: API_KEY_COLUMN_KEYS.ACTIONS, label: "" },
] as const;

export const DEFAULT_EXPIRY_DAYS = "365";
export const ICON_SIZE = 16;

// Fallback values for display
export const FALLBACK_VALUES = {
  UNNAMED: "Unnamed",
  UNNAMED_KEY: "Unnamed Key",
  NEVER: "Never",
  UNKNOWN: "Unknown",
} as const;
