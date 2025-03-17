"use client";

import {
    getProviderLogo,
    getProviderName,
    getProviderVideoLink,
    ProviderType,
  } from "@/components/ui/entities";
import Link from "next/link";

interface CustomProviderInfoProps {
    provider: ProviderType;
  }

  export const CustomProviderInfo = ({ provider }: CustomProviderInfoProps) => {
    return (
      <div className="mb-4 flex items-center space-x-4">
        {provider && getProviderLogo(provider)}
        <span className="text-lg font-semibold">
          {provider ? getProviderName(provider) : "Unknown Provider"}
        </span>
        <p className="align-baseline text-sm text-blue-400">
          {provider && (
            <Link
              href={getProviderVideoLink(provider).link}
              target="_blank"
              rel="noopener noreferrer"
            >
              {getProviderVideoLink(provider).text}
            </Link>
          )}
        </p>
      </div>
    );
  };
