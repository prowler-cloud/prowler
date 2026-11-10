"use client";

import { createContext, Suspense, use } from "react";

import { RegistryProviderLogo } from "@/components/providers/registry-provider-logo";
import type { ProviderType } from "@/types";

const ROW_LOGO_SIZE = 35;

/** Registry logo per provider type, resolved after the rows render. */
export const RegistryLogosContext = createContext<Promise<
  Record<string, string>
> | null>(null);

function ResolvedRegistryRowLogo({
  type,
  logos,
}: {
  type: ProviderType;
  logos: Promise<Record<string, string>>;
}) {
  const byType = use(logos);
  const logoUrl = Object.hasOwn(byType, type) ? byType[type] : undefined;
  return (
    <RegistryProviderLogo type={type} logoUrl={logoUrl} size={ROW_LOGO_SIZE} />
  );
}

/** A registry row's logo; the generic glyph stands in until the logos arrive. */
export function RegistryRowLogo({ type }: { type: ProviderType }) {
  const logos = use(RegistryLogosContext);
  const placeholder = <RegistryProviderLogo type={type} size={ROW_LOGO_SIZE} />;
  if (!logos) return placeholder;
  return (
    <Suspense fallback={placeholder}>
      <ResolvedRegistryRowLogo type={type} logos={logos} />
    </Suspense>
  );
}
