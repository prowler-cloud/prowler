"use client";

import { useState } from "react";

import { Button } from "@/components/shadcn";
import { DialogFooter } from "@/components/shadcn/dialog";
import { Modal } from "@/components/shadcn/modal/modal";
import {
  RadioGroup,
  RadioGroupItem,
} from "@/components/shadcn/radio-group/radio-group";
import {
  DECLARED_CLOUD_ACCOUNTS,
  DECLARED_ROLE,
  DECLARED_ROLE_LABEL,
  DECLARED_TEAM_SIZE,
  type DeclaredCloudAccounts,
  type DeclaredRole,
  type DeclaredTeamSize,
  type OnboardingProfileAnswers,
} from "@/types/onboarding-profile";

interface OnboardingProfileModalProps {
  open: boolean;
  isSubmitting?: boolean;
  onSubmit: (answers: OnboardingProfileAnswers) => void;
  onSkip: () => void;
}

interface ProfileQuestionProps<Value extends string> {
  name: string;
  legend: string;
  options: readonly Value[];
  labels?: Partial<Record<Value, string>>;
  value: Value | null;
  onChange: (value: Value) => void;
  disabled: boolean;
}

interface ProfileDraft {
  cloudAccounts: DeclaredCloudAccounts | null;
  teamSize: DeclaredTeamSize | null;
  role: DeclaredRole | null;
}

const EMPTY_DRAFT: ProfileDraft = {
  cloudAccounts: null,
  teamSize: null,
  role: null,
};

function ProfileQuestion<Value extends string>({
  name,
  legend,
  options,
  labels,
  value,
  onChange,
  disabled,
}: ProfileQuestionProps<Value>) {
  return (
    <fieldset className="flex flex-col gap-2">
      <legend className="text-text-neutral-primary mb-2 text-sm font-medium">
        {legend}
      </legend>
      <RadioGroup
        name={name}
        value={value ?? ""}
        onValueChange={(next) => onChange(next as Value)}
        disabled={disabled}
        className="flex flex-row flex-wrap gap-x-6 gap-y-2"
        aria-label={legend}
      >
        {options.map((option) => (
          <label
            key={option}
            className="text-text-neutral-secondary flex items-center gap-2 text-sm"
          >
            <RadioGroupItem
              value={option}
              aria-label={labels?.[option] ?? option}
            />
            {labels?.[option] ?? option}
          </label>
        ))}
      </RadioGroup>
    </fieldset>
  );
}

// Three closed questions asked once, at a new tenant's first login, before
// any product signal could shape the answer. Every path out is recorded by
// the caller: submit, skip, and close (which counts as a skip).
export function OnboardingProfileModal({
  open,
  isSubmitting = false,
  onSubmit,
  onSkip,
}: OnboardingProfileModalProps) {
  const [draft, setDraft] = useState<ProfileDraft>(EMPTY_DRAFT);
  const isComplete =
    draft.cloudAccounts !== null &&
    draft.teamSize !== null &&
    draft.role !== null;

  const handleSubmit = () => {
    const { cloudAccounts, teamSize, role } = draft;
    if (cloudAccounts === null || teamSize === null || role === null) return;
    if (isSubmitting) return;
    onSubmit({
      declared_cloud_accounts: cloudAccounts,
      declared_team_size: teamSize,
      declared_role: role,
    });
  };

  return (
    <Modal
      open={open}
      title="Tell us about your setup"
      description="Three quick questions so Prowler Cloud fits how you work. You can skip them."
      size="lg"
      // Overlay/Escape/X counts as a skip — the gate persists the marker once.
      onOpenChange={(next) => {
        if (!next && !isSubmitting) onSkip();
      }}
    >
      <div className="flex flex-col gap-6">
        <ProfileQuestion
          name="declared_cloud_accounts"
          legend="How many cloud accounts do you manage?"
          options={Object.values(DECLARED_CLOUD_ACCOUNTS)}
          value={draft.cloudAccounts}
          onChange={(cloudAccounts) =>
            setDraft((current) => ({ ...current, cloudAccounts }))
          }
          disabled={isSubmitting}
        />
        <ProfileQuestion
          name="declared_team_size"
          legend="How many people are on your security or platform team?"
          options={Object.values(DECLARED_TEAM_SIZE)}
          value={draft.teamSize}
          onChange={(teamSize) =>
            setDraft((current) => ({ ...current, teamSize }))
          }
          disabled={isSubmitting}
        />
        <ProfileQuestion
          name="declared_role"
          legend="What is your role?"
          options={Object.values(DECLARED_ROLE)}
          labels={DECLARED_ROLE_LABEL}
          value={draft.role}
          onChange={(role) => setDraft((current) => ({ ...current, role }))}
          disabled={isSubmitting}
        />
      </div>
      <DialogFooter>
        {/* Outline matches the app's modal secondary action (e.g. Launch Scan's Cancel). */}
        <Button variant="outline" onClick={onSkip} disabled={isSubmitting}>
          Skip
        </Button>
        <Button onClick={handleSubmit} disabled={!isComplete || isSubmitting}>
          {isSubmitting ? "Saving..." : "Continue"}
        </Button>
      </DialogFooter>
    </Modal>
  );
}
