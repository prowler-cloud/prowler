import { http, HttpResponse } from "msw";

// A 1×1 transparent PNG.
const PNG = Uint8Array.from(
  atob(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
  ),
  (char) => char.charCodeAt(0),
);

/** Serves a registry logo image, so a test never reaches the real registry. */
export function handleRegistryLogo(url: string) {
  return http.get(
    url,
    () => new HttpResponse(PNG, { headers: { "Content-Type": "image/png" } }),
  );
}
