"use client";

import { usePathname } from "next/navigation";
import {
  createContext,
  type ReactNode,
  use,
  useEffect,
  useEffectEvent,
  useRef,
  useState,
} from "react";

import { refreshRegistryEligibility } from "@/actions/registry/registry";
import {
  REGISTRY_ACCESS,
  type RegistryAccessStatus,
} from "@/lib/registry/access";

type RegistryEligibilityState = {
  status: RegistryAccessStatus;
  generation: number;
  leaseExpiresAt?: number;
};

const RegistryEligibilityContext = createContext<
  | (RegistryEligibilityState & { isEligible: boolean; invalidate: () => void })
  | null
>(null);

export function RegistryEligibilityProvider({
  children,
}: {
  children: ReactNode;
}) {
  const pathname = usePathname();
  const generationRef = useRef(0);
  const [state, setState] = useState<RegistryEligibilityState>({
    status: REGISTRY_ACCESS.UNKNOWN,
    generation: 0,
  });
  const refresh = useEffectEvent(async () => {
    const generation = ++generationRef.current;
    try {
      const result = await refreshRegistryEligibility();
      if (generation !== generationRef.current) return;
      if (result.status === REGISTRY_ACCESS.ELIGIBLE) {
        const leaseExpiresAt = Date.now() + result.leaseDurationMs;
        return setState({ status: result.status, generation, leaseExpiresAt });
      }
      if (result.status === REGISTRY_ACCESS.INELIGIBLE) {
        return setState({ status: result.status, generation });
      }
    } catch {
      if (generation !== generationRef.current) return;
    }
    setState((current) =>
      current.status === REGISTRY_ACCESS.ELIGIBLE &&
      current.leaseExpiresAt !== undefined &&
      current.leaseExpiresAt > Date.now()
        ? { ...current, generation }
        : { status: REGISTRY_ACCESS.UNKNOWN, generation },
    );
  });

  useEffect(() => void refresh(), [pathname]);
  useEffect(() => {
    const refreshVisible = () => {
      if (document.visibilityState === "visible") void refresh();
    };
    window.addEventListener("focus", refreshVisible);
    window.addEventListener("online", refresh);
    document.addEventListener("visibilitychange", refreshVisible);
    return () => {
      window.removeEventListener("focus", refreshVisible);
      window.removeEventListener("online", refresh);
      document.removeEventListener("visibilitychange", refreshVisible);
    };
  }, []);
  useEffect(() => {
    if (state.status !== REGISTRY_ACCESS.ELIGIBLE || !state.leaseExpiresAt)
      return;
    const expire = window.setTimeout(
      () => {
        setState({
          status: REGISTRY_ACCESS.UNKNOWN,
          generation: ++generationRef.current,
        });
      },
      Math.max(0, state.leaseExpiresAt - Date.now()),
    );
    const renew = window.setInterval(() => {
      if (document.visibilityState === "visible") void refresh();
    }, 15_000);
    return () => {
      window.clearTimeout(expire);
      window.clearInterval(renew);
    };
  }, [state.leaseExpiresAt, state.status]);

  const isEligible =
    state.status === REGISTRY_ACCESS.ELIGIBLE &&
    state.leaseExpiresAt !== undefined &&
    Date.now() < state.leaseExpiresAt;
  const invalidate = () =>
    setState({
      status: REGISTRY_ACCESS.INELIGIBLE,
      generation: ++generationRef.current,
    });
  return (
    <RegistryEligibilityContext value={{ ...state, isEligible, invalidate }}>
      {children}
    </RegistryEligibilityContext>
  );
}

export function useRegistryEligibility() {
  const value = use(RegistryEligibilityContext);
  if (!value) throw new Error("RegistryEligibilityProvider is required");
  return value;
}
