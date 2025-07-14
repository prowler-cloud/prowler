import { Bot } from "lucide-react";
import Link from "next/link";

import { getLighthouseConfig } from "@/actions/lighthouse/lighthouse";

interface BannerConfig {
  message: string;
  href: string;
  gradient: string;
}

const renderBanner = ({ message, href, gradient }: BannerConfig) => (
  <Link href={href} className="mb-4 block w-full">
    <div
      className={`w-full rounded-lg ${gradient} shadow-lg transition-all duration-200 hover:shadow-xl focus:outline-none focus:ring-2 focus:ring-opacity-50`}
    >
      <div className="p-6">
        <div className="flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-white/20 backdrop-blur-sm">
            <Bot size={24} className="text-white" />
          </div>
          <div className="text-left">
            <p className="text-xl font-semibold text-white">{message}</p>
          </div>
        </div>
      </div>
    </div>
  </Link>
);

export const LighthouseBanner = async () => {
  try {
    const lighthouseConfig = await getLighthouseConfig();

    if (!lighthouseConfig) {
      return renderBanner({
        message: "Enable Lighthouse to secure your cloud with AI insights",
        href: "/lighthouse/config",
        gradient:
          "bg-gradient-to-r from-green-500 to-blue-500 hover:from-green-600 hover:to-blue-600 focus:ring-green-500/50 dark:from-green-600 dark:to-blue-600 dark:hover:from-green-700 dark:hover:to-blue-700 dark:focus:ring-green-400/50",
      });
    } else {
      return renderBanner({
        message: "Use Lighthouse to review your findings and gain insights",
        href: "/lighthouse",
        gradient:
          "bg-gradient-to-r from-green-500 to-blue-500 hover:from-green-600 hover:to-blue-600 focus:ring-green-500/50 dark:from-green-600 dark:to-blue-600 dark:hover:from-green-700 dark:hover:to-blue-700 dark:focus:ring-green-400/50",
      });
    }
  } catch (error) {
    console.error("Error getting banner state:", error);
    return null;
  }
};
