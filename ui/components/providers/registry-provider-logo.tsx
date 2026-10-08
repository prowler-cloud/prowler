import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import {
  Avatar,
  AvatarFallback,
  AvatarImage,
} from "@/components/shadcn/avatar";
import type { ProviderType } from "@/types";

interface RegistryProviderLogoProps {
  type: ProviderType;
  logoUrl?: string;
  size: number;
}

/** The registry's logo, or the generic glyph while it loads or once its signed URL expires. */
export function RegistryProviderLogo({
  type,
  logoUrl,
  size,
}: RegistryProviderLogoProps) {
  // Same box as a built-in provider badge of this size.
  return (
    <Avatar style={{ width: size, height: size }}>
      <AvatarImage
        src={logoUrl?.startsWith("https://") ? logoUrl : undefined}
        alt=""
      />
      <AvatarFallback>
        <ProviderTypeIcon type={type} size={size} />
      </AvatarFallback>
    </Avatar>
  );
}
