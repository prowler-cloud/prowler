"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

/** One search param that opens and closes a side panel or a view option. */
export function useUrlParam(key: string) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const replaceWith = (value: string | null) => {
    const params = new URLSearchParams(searchParams.toString());
    if (value) params.set(key, value);
    else params.delete(key);
    const query = params.toString();
    router.push(query ? `${pathname}?${query}` : pathname, { scroll: false });
  };

  return {
    value: searchParams.get(key),
    set: (value: string) => replaceWith(value),
    clear: () => replaceWith(null),
  };
}
