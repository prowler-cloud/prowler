export const LIGHTHOUSE_PROVIDERS = [
  "openai",
  "bedrock",
  "openai_compatible",
] as const;

export type LighthouseProvider = (typeof LIGHTHOUSE_PROVIDERS)[number];

export const PROVIDER_DISPLAY_NAMES = {
  openai: "OpenAI",
  bedrock: "Amazon Bedrock",
  openai_compatible: "OpenAI Compatible",
} as const satisfies Record<LighthouseProvider, string>;
