"use client";

import { useRouter } from "next/navigation";
import { type ReactNode, useEffect, useRef, useState } from "react";

import { REGISTRY_ACCESS } from "@/lib/registry/access";

import { useRegistryEligibility } from "./registry-eligibility-provider";

export function RegistryAccessBoundary({
  children,
  initialLeaseDurationMs,
}: {
  children: ReactNode;
  initialLeaseDurationMs: number;
}) {
  const router = useRouter();
  const { generation, isEligible, status } = useRegistryEligibility();
  const expiresAt = useRef(Date.now() + initialLeaseDurationMs);
  const [now, setNow] = useState(Date.now());
  const allowed =
    isEligible ||
    (status === REGISTRY_ACCESS.UNKNOWN &&
      generation <= 1 &&
      now < expiresAt.current);

  useEffect(() => {
    const timer = window.setTimeout(
      () => setNow(Date.now()),
      Math.max(0, expiresAt.current - Date.now()),
    );
    return () => window.clearTimeout(timer);
  }, []);
  useEffect(() => {
    if (!allowed) router.replace("/profile");
  }, [allowed, router]);

  return allowed ? children : null;
}
