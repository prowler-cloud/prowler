"use client";

import { usePathname, useSearchParams } from "next/navigation";

import { compileLighthouseContext } from "@/lib/lighthouse/context/compiler";
import {
  buildLighthousePageContext,
  getLighthouseScopeKey,
  resolveLighthousePage,
  type LighthousePageDefinition,
} from "@/lib/lighthouse/context/pages";
import { useLighthouseContextStore } from "@/store/lighthouse-context/store";
import {
  LIGHTHOUSE_CONTEXT_SOURCE,
  type LighthouseContextEnvelope,
  type LighthouseContextItem,
} from "@/types/lighthouse-context";

export interface LighthouseCurrentContext {
  context: LighthouseContextEnvelope | undefined;
  page: LighthousePageDefinition;
  scopeKey: string;
  selectionCount: number;
}

export function useLighthouseCurrentContext(): LighthouseCurrentContext {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const contributions = useLighthouseContextStore(
    (state) => state.contributions,
  );
  const focused = useLighthouseContextStore((state) => state.focused);

  return buildCurrentLighthouseContext(
    pathname,
    new URLSearchParams(searchParams.toString()),
    Object.values(contributions),
    focused ?? undefined,
  );
}

export function buildCurrentLighthouseContext(
  pathname: string,
  searchParams: URLSearchParams,
  contributions: LighthouseContextItem[],
  focused?: LighthouseContextItem,
): LighthouseCurrentContext {
  const page = resolveLighthousePage(pathname);
  const scopeKey = getLighthouseScopeKey(pathname);
  const pageContext = buildLighthousePageContext(pathname, searchParams);
  const scopedContributions = contributions.filter(
    (item) => item.scopeKey === scopeKey,
  );
  const context = compileLighthouseContext(
    [pageContext, ...(focused ? [focused] : []), ...scopedContributions],
    scopeKey,
  );

  return {
    context,
    page,
    scopeKey,
    selectionCount:
      context?.items.filter(
        (item) =>
          item.source === LIGHTHOUSE_CONTEXT_SOURCE.FOCUSED ||
          item.source === LIGHTHOUSE_CONTEXT_SOURCE.SELECTION,
      ).length ?? 0,
  };
}
