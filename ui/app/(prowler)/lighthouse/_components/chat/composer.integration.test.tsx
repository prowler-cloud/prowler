import type { ReactNode } from "react";
import { describe, expect, it } from "vitest";
import { page } from "vitest/browser";

import { render } from "@/__tests__/render-browser";
import { LighthouseCurrentContextBadge } from "@/components/lighthouse/context-chip";
import { getSkillById } from "@/lib/lighthouse/skills/registry";
import {
  SIDE_PANEL_DEFAULT_WIDTH,
  SIDE_PANEL_MIN_WIDTH,
} from "@/lib/ui-layout";
import type { LighthouseContextEnvelope } from "@/types/lighthouse-context";
import { LIGHTHOUSE_SKILL_ID } from "@/types/lighthouse-skills";

import { ChatComposerPanel } from "./composer";
import { CurrentModelDisplay } from "./current-model-display";
import { ModelSelect } from "./model-select";
import { SkillComposerPill } from "./skill-composer-pill";

const CONNECTION_GUIDE = getSkillById(
  LIGHTHOUSE_SKILL_ID.PROVIDER_CONNECTION_GUIDE,
)!;

const PROVIDERS_CONTEXT: LighthouseContextEnvelope = {
  schemaVersion: 1,
  transport: "inline",
  items: [
    {
      kind: "page",
      id: "providers",
      source: "automatic",
      scopeKey: "providers:/providers",
      label: "Providers",
      path: "/providers",
      filters: {},
    },
  ],
};

// The two model controls the chat view can put in the footer.
const MODEL_CONTROLS = [
  {
    name: "the current model",
    control: (
      <CurrentModelDisplay
        provider="openai"
        providerName="OpenAI"
        modelName="GPT-5.2"
      />
    ),
    locate: () => page.getByLabelText("Current model: OpenAI GPT-5.2"),
    // The part of the control that must stay readable.
    readableText: () => page.getByText("OpenAI", { exact: true }),
  },
  {
    name: "the model picker",
    control: (
      <ModelSelect
        value="openai:gpt-5.2-codex-max"
        onValueChange={() => {}}
        groups={[
          {
            heading: "OpenAI",
            options: [
              { value: "openai:gpt-5.2-codex-max", label: "GPT-5.2 Codex Max" },
            ],
          },
        ]}
        isSaving={false}
      />
    ),
    locate: () => page.getByRole("combobox", { name: "Model" }),
    readableText: () => page.getByText("GPT-5.2 Codex Max"),
  },
];

const PANEL_WIDTHS = [
  { panel: "the narrowest", width: SIDE_PANEL_MIN_WIDTH },
  { panel: "the default", width: SIDE_PANEL_DEFAULT_WIDTH },
];

interface ComposerInPanelProps {
  width: number;
  modelSelector: ReactNode;
}

function ComposerInPanel({ width, modelSelector }: ComposerInPanelProps) {
  return (
    <div style={{ width }}>
      <ChatComposerPanel
        feedback={null}
        canRetry={false}
        onRetry={() => {}}
        onDismissFeedback={() => {}}
        canSend
        input=""
        isStreaming
        modelSelector={modelSelector}
        contextControl={
          <>
            <SkillComposerPill skill={CONNECTION_GUIDE} />
            <LighthouseCurrentContextBadge context={PROVIDERS_CONTEXT} />
          </>
        }
        selectedConfigurationConnected
        onInputChange={() => {}}
        onSubmit={(event) => event.preventDefault()}
        onSubmitText={async () => {}}
      />
    </div>
  );
}

function overlaps(a: DOMRect, b: DOMRect) {
  return (
    a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom
  );
}

function isInside(inner: DOMRect, outer: DOMRect) {
  return inner.left >= outer.left && inner.right <= outer.right;
}

describe("Lighthouse composer footer", () => {
  it.each(
    MODEL_CONTROLS.flatMap((model) =>
      PANEL_WIDTHS.map((panel) => ({ ...model, ...panel })),
    ),
  )(
    "keeps $name, the running skill and the context apart in $panel side panel",
    async ({ control, locate, readableText, width }) => {
      // Given / When: a skill runs while the chat sits in the side panel
      render(<ComposerInPanel width={width - 32} modelSelector={control} />);
      const model = locate();
      await expect.element(model).toBeVisible();

      // Then: no control covers another or leaves the composer
      const composerBox = page
        .getByLabelText("Message")
        .element()
        .closest("form")!
        .getBoundingClientRect();
      const modelBox = model.element().getBoundingClientRect();
      const skillBox = page
        .getByText("Skill · Connection Guide")
        .element()
        .closest('[role="status"]')!
        .getBoundingClientRect();
      const contextBox = page
        .getByLabelText("Providers context")
        .element()
        .getBoundingClientRect();

      expect(overlaps(modelBox, skillBox)).toBe(false);
      expect(overlaps(modelBox, contextBox)).toBe(false);
      expect(overlaps(skillBox, contextBox)).toBe(false);
      for (const box of [modelBox, skillBox, contextBox]) {
        expect(isInside(box, composerBox)).toBe(true);
      }
      // And the model stays readable: whole, and inside its own control
      const text = readableText().element() as HTMLElement;
      expect(text.scrollWidth).toBeLessThanOrEqual(text.clientWidth);
      expect(text.getBoundingClientRect().right).toBeLessThanOrEqual(
        modelBox.right,
      );
    },
  );
});
