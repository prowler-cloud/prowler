import { GenericProviderBadge } from "@/components/icons/providers-badge/generic-provider-badge";
import {
  Avatar,
  AvatarFallback,
  AvatarImage,
} from "@/components/shadcn/avatar";

interface RegistryProviderLogoProps {
  logoUrl?: string;
  size: number;
}

/** The registry's logo, or the generic glyph while it loads or once its signed URL expires. */
export function RegistryProviderLogo({
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
        <GenericProviderBadge size={size} />
      </AvatarFallback>
    </Avatar>
  );
}
