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

function ComposerInPanel({ width }: { width: number }) {
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
        modelSelector={
          <CurrentModelDisplay
            provider="openai"
            providerName="OpenAI"
            modelName="GPT-5.2"
          />
        }
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

describe("Lighthouse composer footer", () => {
  it.each([
    ["the narrowest", SIDE_PANEL_MIN_WIDTH],
    ["the default", SIDE_PANEL_DEFAULT_WIDTH],
  ])(
    "keeps the model, the running skill and the context apart in %s side panel",
    async (_, panelWidth) => {
      // Given / When: a skill runs while the chat sits in the side panel
      render(<ComposerInPanel width={panelWidth - 32} />);
      const model = page.getByLabelText("Current model: OpenAI GPT-5.2");
      await expect.element(model).toBeVisible();

      // Then: no chip covers another, and the model stays readable
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
      const providerNameBox = page
        .getByText("OpenAI", { exact: true })
        .element()
        .getBoundingClientRect();

      expect(overlaps(modelBox, skillBox)).toBe(false);
      expect(overlaps(modelBox, contextBox)).toBe(false);
      expect(overlaps(skillBox, contextBox)).toBe(false);
      expect(providerNameBox.right).toBeLessThanOrEqual(modelBox.right);
    },
  );
});
