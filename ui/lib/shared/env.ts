/**
 * Shared environment helpers.
 */

/**
 * Whether the UI is running inside a Prowler Cloud deployment.
 *
 * `NEXT_PUBLIC_*` vars are statically inlined by Next.js wherever the literal
 * `process.env.NEXT_PUBLIC_IS_CLOUD_ENV` appears in source, so keeping this read
 * inside a helper is safe.
 */
export function isCloud(): boolean {
  return process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";
}
