"use client";

import { useRouter } from "next/navigation";
import { useEffect, useTransition } from "react";

interface AutoRefreshProps {
  hasExecutingScan: boolean;
}

export function AutoRefresh({ hasExecutingScan }: AutoRefreshProps) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();

  useEffect(() => {
    if (!hasExecutingScan) return;

    const refreshPage = () => {
      startTransition(() => {
        const url = new URL(window.location.href);
        url.searchParams.set("_refresh", Date.now().toString());
        router.replace(url.pathname + url.search);
      });
    };

    refreshPage();

    const interval = setInterval(refreshPage, 5000);

    return () => clearInterval(interval);
  }, [hasExecutingScan, router]);

  return null;
}
