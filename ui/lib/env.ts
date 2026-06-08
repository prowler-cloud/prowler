import { readEnv } from "@/lib/runtime-env";

// Boot-time required-env assertion so a misconfigured container fails fast
// with a clear message. A key with a deprecated legacy name is satisfied by
// either name (see readEnv).
const REQUIRED: ReadonlyArray<{
  key: keyof NodeJS.ProcessEnv;
  legacy?: keyof NodeJS.ProcessEnv;
}> = [
  { key: "UI_API_BASE_URL", legacy: "NEXT_PUBLIC_API_BASE_URL" },
  { key: "AUTH_URL" },
  { key: "AUTH_SECRET" },
];

for (const { key, legacy } of REQUIRED) {
  if (!readEnv(key, legacy)) {
    throw new Error(`Missing required env: ${key}`);
  }
}

export {};
