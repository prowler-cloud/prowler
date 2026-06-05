// Boot-time required-env assertion so a misconfigured container fails fast
// with a clear message.
const REQUIRED = [
  "WEB_APP_API_BASE_URL",
  "AUTH_URL",
  "AUTH_SECRET",
] as const satisfies ReadonlyArray<keyof NodeJS.ProcessEnv>;

for (const key of REQUIRED) {
  if (!process.env[key]) {
    throw new Error(`Missing required env: ${key}`);
  }
}

export {};
