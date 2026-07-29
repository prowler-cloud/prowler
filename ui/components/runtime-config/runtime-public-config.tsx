import { getRuntimePublicConfig } from "@/lib/runtime-config";
import { RUNTIME_CONFIG_SCRIPT_ID } from "@/lib/runtime-config.shared";
import { serializeForScript } from "@/lib/safe-json";

// Inert JSON config island (type="application/json") rendered in <head> before
// the client bundle, so module-load consumers (Sentry init) read it race-free.
export async function RuntimePublicConfig() {
  const config = await getRuntimePublicConfig();

  return (
    <script
      id={RUNTIME_CONFIG_SCRIPT_ID}
      type="application/json"
      dangerouslySetInnerHTML={{ __html: serializeForScript(config) }}
    />
  );
}
