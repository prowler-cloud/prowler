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
  const refresh = useEffectEvent(async (invalidate: boolean) => {
    const generation = ++generationRef.current;
    if (invalidate) setState({ status: REGISTRY_ACCESS.UNKNOWN, generation });
    try {
      const result = await refreshRegistryEligibility();
      if (generation !== generationRef.current) return;
      setState(
        result.status === REGISTRY_ACCESS.ELIGIBLE
          ? {
              status: result.status,
              generation,
              leaseExpiresAt: Date.now() + result.leaseDurationMs,
            }
          : { status: result.status, generation },
      );
    } catch {
      if (generation === generationRef.current) {
        setState({ status: REGISTRY_ACCESS.UNKNOWN, generation });
      }
    }
  });

  useEffect(() => void refresh(true), [pathname]);
  useEffect(() => {
    const refreshVisible = () => {
      if (document.visibilityState === "visible") void refresh(true);
    };
    const refreshOnline = () => void refresh(true);
    window.addEventListener("focus", refreshVisible);
    window.addEventListener("online", refreshOnline);
    document.addEventListener("visibilitychange", refreshVisible);
    return () => {
      window.removeEventListener("focus", refreshVisible);
      window.removeEventListener("online", refreshOnline);
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
      if (document.visibilityState === "visible") void refresh(false);
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
      status: REGISTRY_ACCESS.UNKNOWN,
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
