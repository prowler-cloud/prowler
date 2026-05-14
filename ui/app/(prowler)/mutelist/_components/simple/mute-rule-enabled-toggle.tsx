"use client";

import { Switch } from "@heroui/switch";
import { useState } from "react";

import { toggleMuteRule } from "@/actions/mute-rules";
import { MuteRuleData } from "@/actions/mute-rules/types";
import { useToast } from "@/components/ui";

interface MuteRuleEnabledToggleProps {
  muteRule: MuteRuleData;
}

export function MuteRuleEnabledToggle({
  muteRule,
}: MuteRuleEnabledToggleProps) {
  const [isEnabled, setIsEnabled] = useState(muteRule.attributes.enabled);
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();

  const handleToggle = async (value: boolean) => {
    setIsLoading(true);
    setIsEnabled(value);

    const result = await toggleMuteRule(muteRule.id, value);

    if (result.error) {
      // Revert on error
      setIsEnabled(!value);
      toast({
        variant: "destructive",
        title: "Error",
        description: result.error,
      });
    } else if (result.success) {
      toast({
        title: "Success",
        description: result.success,
      });
    }

    setIsLoading(false);
  };

  return (
    <Switch
      isSelected={isEnabled}
      onValueChange={handleToggle}
      isDisabled={isLoading}
      size="sm"
      aria-label={`Toggle mute rule ${muteRule.attributes.name}`}
    />
  );
}
