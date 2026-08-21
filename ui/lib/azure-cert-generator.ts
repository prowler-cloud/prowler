// In-browser X.509 self-signed certificate generator for the Azure
// certificate-authentication onboarding flow.
//
// The keypair is generated with the browser's native Web Crypto API
// (`crypto.subtle.generateKey`) and never leaves the tab. `@peculiar/x509`
// wraps the public key in a self-signed X.509 certificate whose SHA-1
// thumbprint we can hand back to the user; the private key is exported as
// base64-encoded PEM ready to paste into the Prowler wizard's Certificate
// Private Key field.
//
// See the certificate authentication guide in
// docs/user-guide/providers/azure/authentication.mdx for the equivalent
// openssl/PowerShell recipes, and PROWLER-2378 for the Deploy-to-Azure
// quick-start feature this UX affordance belongs to.

// `@peculiar/x509` transitively depends on `tsyringe`, which pulls in a
// decorators/DI runtime that requires the `reflect-metadata` polyfill. The
// import has to happen before anything from `@peculiar/x509` is imported so
// the metadata store is registered on `Reflect` first.
import "reflect-metadata";

import {
  cryptoProvider,
  Extension,
  X509CertificateGenerator,
} from "@peculiar/x509";

export interface GeneratedProwlerCertificate {
  /**
   * Base64 of the DER-encoded X.509 public certificate. The download helper
   * converts this value into the `.cer` file uploaded to the App Registration.
   */
  publicCertificateBase64Der: string;
  /**
   * Base64 of the PEM bundle containing both the X.509 certificate and the
   * PKCS#8 private key. `azure.identity.CertificateCredential` accepts this
   * exact shape; the Prowler wizard pastes it into the Certificate Private
   * Key (Base64) textarea.
   */
  privateKeyBundleBase64Pem: string;
  /** Human-readable SHA-1 thumbprint, uppercase hex, matching what Entra ID displays. */
  thumbprintHex: string;
  /** ISO 8601 not-valid-before timestamp of the generated cert. */
  notBefore: string;
  /** ISO 8601 not-valid-after timestamp of the generated cert. */
  notAfter: string;
}

export interface GenerateProwlerCertificateOptions {
  /**
   * Common name to embed in the certificate subject. Defaults to "Prowler"
   * to match the openssl/PowerShell examples in the docs.
   */
  commonName?: string;
  /** Certificate lifetime in days. Default 365. */
  validityDays?: number;
  /** RSA modulus length. Default 4096 (matches the openssl example). */
  modulusLength?: 2048 | 3072 | 4096;
  /**
   * Injected clock for deterministic tests. Defaults to `Date.now()`.
   */
  now?: () => Date;
}

const DEFAULTS: Required<
  Pick<
    GenerateProwlerCertificateOptions,
    "commonName" | "validityDays" | "modulusLength"
  >
> = {
  commonName: "Prowler",
  validityDays: 365,
  modulusLength: 4096,
};

/**
 * Generate a fresh self-signed X.509 certificate + RSA-4096 keypair in the
 * browser. Nothing crosses the network — the private key exists only in the
 * returned object and inside the caller's memory.
 *
 * Throws when the browser does not expose SubtleCrypto (e.g. insecure origin
 * or old browser). Callers should surface a friendly fallback ("use openssl
 * instead") when that happens.
 */
export async function generateProwlerCertificate(
  options: GenerateProwlerCertificateOptions = {},
): Promise<GeneratedProwlerCertificate> {
  const commonName = options.commonName ?? DEFAULTS.commonName;
  const validityDays = options.validityDays ?? DEFAULTS.validityDays;
  const modulusLength = options.modulusLength ?? DEFAULTS.modulusLength;
  const now = options.now ?? (() => new Date());

  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error(
      "Web Crypto API is not available in this browser. Use the openssl or PowerShell instructions from the certificate generation guide instead.",
    );
  }
  // Bind @peculiar/x509 to the browser's native SubtleCrypto here rather
  // than at module load time: doing it inside the function keeps the check
  // above authoritative (the crypto object could have been swapped by a
  // test harness between import and call) and avoids side-effects when
  // consumers only import the types.
  cryptoProvider.set(globalThis.crypto);

  const keyPair = (await subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;

  const notBefore = now();
  const notAfter = new Date(
    notBefore.getTime() + validityDays * 24 * 60 * 60 * 1000,
  );

  const cert = await X509CertificateGenerator.createSelfSigned({
    // Random serial: 16 hex chars is plenty for identification purposes and
    // matches how `openssl x509 -req` chooses serials by default.
    serialNumber: randomHex(16),
    name: `CN=${commonName}`,
    notBefore,
    notAfter,
    signingAlgorithm: {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    keys: keyPair,
    extensions: [] as Extension[],
  });

  const certPem = cert.toString("pem");
  const certDer = new Uint8Array(cert.rawData);
  const publicCertificateBase64Der = toBase64(certDer);

  const privateKeyPkcs8 = new Uint8Array(
    await subtle.exportKey("pkcs8", keyPair.privateKey),
  );
  const privateKeyPem = pkcs8ToPem(privateKeyPkcs8);

  // Bundle order matches what azure-identity expects: certificate first,
  // private key second. The full bundle is then base64-encoded so it can
  // live inside a single form field / JSON payload.
  const bundlePem = `${certPem.trim()}\n${privateKeyPem.trim()}\n`;
  const privateKeyBundleBase64Pem = toBase64(
    new TextEncoder().encode(bundlePem),
  );

  const thumbprintBytes = new Uint8Array(await subtle.digest("SHA-1", certDer));
  const thumbprintHex = bytesToHexUpper(thumbprintBytes);

  return {
    publicCertificateBase64Der,
    privateKeyBundleBase64Pem,
    thumbprintHex,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
  };
}

/**
 * Trigger a browser download of the public certificate as a `.cer` file (raw
 * DER bytes) so the user can upload it directly on the App Registration's
 * *Certificates* blade in the Azure Portal — no terminal step or manual
 * base64 decoding required.
 *
 * The Portal upload accepts `.cer`, `.pem` and `.crt`; we emit `.cer` because
 * it matches the raw DER bytes we already have and is the extension the
 * Portal upload dialog shows first.
 *
 * Split from `generateProwlerCertificate` so the pure generator can be unit
 * tested without stubbing `document.createElement`.
 */
export function downloadPublicCertificateFile(
  publicCertificateBase64Der: string,
  filename = "prowler-cert.cer",
): void {
  const derBytes = base64ToBytes(publicCertificateBase64Der);
  const blob = new Blob([derBytes as BlobPart], {
    type: "application/x-x509-ca-cert",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  // Free the blob URL immediately; the browser has already started the
  // download at this point, so revoking is safe.
  URL.revokeObjectURL(url);
}

// -- helpers ---------------------------------------------------------------

/**
 * Uint8Array → base64. Kept private to this module because the codebase does
 * not yet have a shared helper and this one only needs to handle small
 * payloads (a cert + key are ~5 KB total). If a shared helper appears later,
 * swap this out.
 */
function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/**
 * Inverse of `toBase64` — decode a base64 string back to raw bytes. Only used
 * by `downloadPublicCertificateFile` to reconstitute the DER blob for the
 * `.cer` download; the generator itself works in raw bytes end-to-end.
 */
function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function randomHex(chars: number): string {
  const bytes = new Uint8Array(Math.ceil(chars / 2));
  globalThis.crypto.getRandomValues(bytes);
  return bytesToHexUpper(bytes).slice(0, chars);
}

function bytesToHexUpper(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    hex += byte.toString(16).padStart(2, "0").toUpperCase();
  }
  return hex;
}

// `@peculiar/x509` exports certs to PEM directly but not PKCS#8 keys — we
// build the PEM ourselves so the private key format is deterministic and
// matches what `openssl pkey -inform DER` would emit.
function pkcs8ToPem(pkcs8: Uint8Array): string {
  const base64 = toBase64(pkcs8);
  // 64-char lines is the classic PEM formatting; azure-identity and every
  // other PEM parser accept both wrapped and unwrapped, but wrapping keeps
  // the file human-readable.
  const wrapped = base64.match(/.{1,64}/g)?.join("\n") ?? base64;
  return `-----BEGIN PRIVATE KEY-----\n${wrapped}\n-----END PRIVATE KEY-----`;
}

// Named export needed by @/lib/shared/base64 fallback below.
export const __internal = { pkcs8ToPem, bytesToHexUpper, randomHex };
