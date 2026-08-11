import { webcrypto } from "node:crypto";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import {
  downloadPublicCertificateFile,
  generateProwlerCertificate,
} from "./azure-cert-generator";

// jsdom exposes `globalThis.crypto` but historically without a working
// `subtle` implementation. Node 20+ ships one on `node:crypto.webcrypto`
// that satisfies both @peculiar/x509 and our helper. Bind it once so the
// module-level `cryptoProvider.set(...)` inside the SUT resolves it.
beforeAll(() => {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    Object.defineProperty(globalThis, "crypto", {
      value: webcrypto,
      configurable: true,
      writable: true,
    });
  }
});

describe("generateProwlerCertificate", () => {
  it("produces a certificate + private-key bundle that round-trips through PEM parsers", async () => {
    // Given / When
    const result = await generateProwlerCertificate({
      // Shrink the modulus so the test finishes in <2s under CI without
      // giving up any of the code paths the helper touches at 4096 bits.
      modulusLength: 2048,
      commonName: "prowler-test",
      validityDays: 30,
    });

    // Then — DER base64 of the public certificate decodes to a byte array
    // that starts with the ASN.1 SEQUENCE tag (0x30). A stray bug that
    // returned PEM instead of DER, or double-encoded the base64, would trip
    // this straight away.
    const publicDer = Uint8Array.from(
      atob(result.publicCertificateBase64Der),
      (c) => c.charCodeAt(0),
    );
    expect(publicDer[0]).toBe(0x30);
    expect(publicDer.byteLength).toBeGreaterThan(500);

    // The private-key bundle decodes to a UTF-8 PEM string containing both
    // markers, in the order azure-identity expects (cert first, key second).
    const bundlePem = new TextDecoder().decode(
      Uint8Array.from(atob(result.privateKeyBundleBase64Pem), (c) =>
        c.charCodeAt(0),
      ),
    );
    const certIdx = bundlePem.indexOf("-----BEGIN CERTIFICATE-----");
    const keyIdx = bundlePem.indexOf("-----BEGIN PRIVATE KEY-----");
    expect(certIdx).toBeGreaterThanOrEqual(0);
    expect(keyIdx).toBeGreaterThan(certIdx);
    expect(bundlePem).toContain("-----END CERTIFICATE-----");
    expect(bundlePem).toContain("-----END PRIVATE KEY-----");

    // Validity window respects the injected days and is a real ISO 8601
    // timestamp.
    const notBefore = new Date(result.notBefore);
    const notAfter = new Date(result.notAfter);
    expect(notBefore.getTime()).toBeLessThan(notAfter.getTime());
    const days = (notAfter.getTime() - notBefore.getTime()) / 86_400_000;
    expect(days).toBeCloseTo(30, 0);
  });

  it("returns the correct SHA-1 thumbprint format expected by Entra ID", async () => {
    // Given / When
    const result = await generateProwlerCertificate({ modulusLength: 2048 });

    // Then — 40 hex chars, uppercase, no separators.
    expect(result.thumbprintHex).toMatch(/^[0-9A-F]{40}$/);
  });

  it("throws a friendly error when SubtleCrypto is unavailable", async () => {
    // Given the browser doesn't expose subtle (insecure origin, ancient
    // browser, some sandboxes).
    const originalCrypto = globalThis.crypto;
    Object.defineProperty(globalThis, "crypto", {
      value: {},
      configurable: true,
      writable: true,
    });

    // When / Then
    await expect(generateProwlerCertificate()).rejects.toThrow(
      /Web Crypto API is not available/i,
    );

    // Cleanup
    Object.defineProperty(globalThis, "crypto", {
      value: originalCrypto,
      configurable: true,
      writable: true,
    });
  });
});

describe("downloadPublicCertificateFile", () => {
  const originalCreateElement = document.createElement.bind(document);
  const originalCreateObjectURL = URL.createObjectURL;
  const originalRevokeObjectURL = URL.revokeObjectURL;

  afterEach(() => {
    document.createElement = originalCreateElement;
    URL.createObjectURL = originalCreateObjectURL;
    URL.revokeObjectURL = originalRevokeObjectURL;
  });

  it("triggers an anchor click with the right href and filename, then revokes the blob URL", () => {
    // Given
    const clickSpy = vi.fn();
    const objectUrl = "blob:mock/prowler-cert";
    URL.createObjectURL = vi.fn(() => objectUrl);
    const revokeSpy = vi.fn();
    URL.revokeObjectURL = revokeSpy;

    // The anchor spy is a real HTMLAnchorElement so `document.body.appendChild`
    // and `removeChild` accept it; we only intercept the `click` method.
    const realAnchor = originalCreateElement("a");
    realAnchor.click = clickSpy;
    document.createElement = vi.fn((tag: string) => {
      if (tag === "a") return realAnchor;
      return originalCreateElement(tag);
    }) as typeof document.createElement;

    // When
    downloadPublicCertificateFile("MIIBase64Contents", "prowler-cert.txt");

    // Then
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
    expect(clickSpy).toHaveBeenCalledTimes(1);
    expect(realAnchor.href).toContain(objectUrl);
    expect(realAnchor.download).toBe("prowler-cert.txt");
    // Revoked to avoid leaking the blob URL for the tab's lifetime.
    expect(revokeSpy).toHaveBeenCalledWith(objectUrl);
  });

  it("defaults the filename when the caller omits it", () => {
    // Given
    URL.createObjectURL = vi.fn(() => "blob:mock");
    URL.revokeObjectURL = vi.fn();
    const realAnchor = originalCreateElement("a");
    realAnchor.click = vi.fn();
    document.createElement = vi.fn((tag: string) => {
      if (tag === "a") return realAnchor;
      return originalCreateElement(tag);
    }) as typeof document.createElement;

    // When
    downloadPublicCertificateFile("payload");

    // Then
    expect(realAnchor.download).toBe("prowler-cert-base64.txt");
  });
});
