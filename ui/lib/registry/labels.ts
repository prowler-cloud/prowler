// Only plain lowercase identifiers: "us-east-1" or "OAuth2" already read as meant.
const PLAIN_IDENTIFIER = /^[a-z][a-z0-9]*(?:[_ ][a-z0-9]+)*$/;

/** Display text for a Registry identifier ("service_account" → "Service account"). */
export function formatRegistryLabel(value: string): string {
  if (!PLAIN_IDENTIFIER.test(value)) return value;
  const words = value.replaceAll("_", " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}
