"use client";

import { Bot } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

interface Nudge {
  nudge: string;
  llm_query: string;
}

interface NudgeResponse {
  nudges: Nudge[];
}

interface LighthouseBannerProps {
  initialNudges: NudgeResponse;
}

export function LighthouseBanner({ initialNudges }: LighthouseBannerProps) {
  const [displayText, setDisplayText] = useState<string>("");
  const [nudges, setNudges] = useState<NudgeResponse>(initialNudges);
  const [currentNudge, setCurrentNudge] = useState<Nudge | null>(null);

  // Function to fetch updated nudges
  const fetchNudges = async () => {
    try {
      const response = await fetch("/api/lighthouse/nudge");
      if (response.ok) {
        const data = await response.json();
        setNudges(data);
      }
    } catch (error) {
      console.error("Error fetching nudges:", error);
    }
  };

  // Determine navigation path based on nudge type
  const getNavigationPath = () => {
    if (!currentNudge) return "/lighthouse";

    // If llm_query is empty, it's a configuration nudge (default nudges)
    // If llm_query exists, it's an AI-generated analysis nudge
    const isConfigurationNudge =
      !currentNudge.llm_query || currentNudge.llm_query.trim() === "";

    if (isConfigurationNudge) {
      return "/lighthouse/config";
    } else {
      // For analysis nudges, pass the llm_query as a URL parameter
      const encodedQuery = encodeURIComponent(currentNudge.llm_query);
      return `/lighthouse?query=${encodedQuery}`;
    }
  };

  useEffect(() => {
    if (!nudges.nudges || nudges.nudges.length === 0) {
      // No nudges available - poll every 30 seconds to check for new ones
      const pollInterval = setInterval(() => {
        fetchNudges();
      }, 30000); // 30 seconds

      return () => clearInterval(pollInterval);
    } else {
      // Has nudges - cycle through them
      setDisplayText(nudges.nudges[0].nudge);
      setCurrentNudge(nudges.nudges[0]);
      let currentIndex = 0;

      const cycleInterval = setInterval(() => {
        currentIndex = (currentIndex + 1) % nudges.nudges.length;
        setDisplayText(nudges.nudges[currentIndex].nudge);
        setCurrentNudge(nudges.nudges[currentIndex]);
      }, 30000); // 30 seconds

      return () => clearInterval(cycleInterval);
    }
  }, [nudges]);

  // Don't render anything if no nudges are available
  if (!nudges.nudges || nudges.nudges.length === 0) {
    return null;
  }

  return (
    <div className="mb-6">
      <div className="mb-2 text-xs font-medium text-slate-500">
        AI-Powered Security Analysis
      </div>
      <Link href={getNavigationPath()} className="block">
        <div className="group relative cursor-pointer overflow-hidden rounded-xl border border-slate-600 bg-gradient-to-br from-slate-800 to-slate-900 transition-all duration-200 hover:-translate-y-0.5 hover:border-slate-500 hover:from-slate-700 hover:to-slate-800">
          {/* Left gradient accent bar */}
          <div className="absolute bottom-0 left-0 top-0 w-1 bg-gradient-to-b from-purple-500 to-violet-600"></div>

          <div className="flex items-center gap-4 p-5 pl-6">
            {/* Bot icon */}
            <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-purple-500 to-violet-600">
              <Bot className="h-6 w-6 text-white" />
            </div>

            {/* Content */}
            <div className="flex-1">
              <p className="text-lg font-medium leading-relaxed text-white">
                {displayText}
              </p>
            </div>
          </div>
        </div>
      </Link>
    </div>
  );
}
