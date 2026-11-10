import type { ReactNode } from "react";
import { useForm } from "react-hook-form";
import { describe, expect, it } from "vitest";

import { handleRegistryLogo } from "@/__tests__/msw/handlers/registry";
import { worker } from "@/__tests__/msw/worker";
import { render } from "@/__tests__/render-browser";
import type { AddProviderFormValues } from "@/types/formSchemas";

import { RadioGroupProvider } from "./radio-group-provider";

// Keep even speculative browser requests on loopback; MSW serves the image.
const LOGO_URL = "https://127.0.0.1/providers/vcf/logo.png";

const LONG_LABEL =
  "Acme Sovereign Multi Region Enterprise Compliance Cloud Platform";

function Selector({
  registryLoading = false,
  registryLabel = "Vcf",
}: {
  registryLoading?: boolean;
  registryLabel?: string;
}) {
  const form = useForm<AddProviderFormValues>();
  return (
    <RadioGroupProvider
      control={form.control}
      isInvalid={false}
      registryAvailable
      registryLoading={registryLoading}
      registryOptions={[
        {
          type: "vcf",
          label: registryLabel,
          logoUrl: LOGO_URL,
        },
      ]}
    />
  );
}

// Like the wizard: a marked size container holding the form column.
function InWizard({ width, children }: { width: number; children: ReactNode }) {
  return (
    <div data-responsive-container className="@container" style={{ width }}>
      <div className="lg:ml-auto lg:max-w-[700px]">{children}</div>
    </div>
  );
}

const boxOf = (element: Element) => element.getBoundingClientRect();

// The logo is the first element of the option's label row.
function logoBox(option: HTMLElement) {
  const logo = option.lastElementChild?.firstElementChild;
  if (!logo) throw new Error("Provider option without a logo");
  const { width, height } = logo.getBoundingClientRect();
  return { width, height };
}

describe("provider selector logos", () => {
  it("draws a Registry provider's logo at the size of the built-in logos", async () => {
    // Given
    worker.use(handleRegistryLogo(LOGO_URL));
    const screen = await render(<Selector />);

    // When
    const builtIn = screen
      .getByRole("option", { name: "Amazon Web Services" })
      .element() as HTMLElement;
    const registry = screen
      .getByRole("option", { name: "Vcf Registry" })
      .element() as HTMLElement;
    await expect
      .poll(() => registry.querySelector("img")?.getAttribute("src"))
      .toBe(LOGO_URL);
    await expect
      .poll(() => registry.querySelector("img")?.naturalWidth)
      .toBe(1);

    // Then
    expect(logoBox(registry)).toEqual(logoBox(builtIn));
  });
});

describe("provider selector layout", () => {
  it("lists two providers per row beside a wide wizard", async () => {
    // When
    const screen = await render(
      <InWizard width={1200}>
        <Selector />
      </InWizard>,
    );

    // Then
    const aws = boxOf(
      screen.getByRole("option", { name: "Amazon Web Services" }).element(),
    );
    const azure = boxOf(
      screen.getByRole("option", { name: "Microsoft Azure" }).element(),
    );
    const gcp = boxOf(
      screen.getByRole("option", { name: "Google Cloud Platform" }).element(),
    );
    expect(azure.top).toBe(aws.top);
    expect(azure.left).toBeGreaterThan(aws.right);
    expect(gcp.top).toBeGreaterThan(aws.bottom);
  });

  it("keeps one provider per row while the wizard stacks", async () => {
    // When
    const screen = await render(
      <InWizard width={720}>
        <Selector />
      </InWizard>,
    );

    // Then
    const aws = boxOf(
      screen.getByRole("option", { name: "Amazon Web Services" }).element(),
    );
    const azure = boxOf(
      screen.getByRole("option", { name: "Microsoft Azure" }).element(),
    );
    expect(azure.top).toBeGreaterThan(aws.bottom);
  });

  it("cuts a long name with an ellipsis inside its card", async () => {
    // When
    const screen = await render(
      <InWizard width={1200}>
        <Selector registryLabel={LONG_LABEL} />
      </InWizard>,
    );

    // Then
    const long = screen
      .getByRole("option", { name: `${LONG_LABEL} Registry` })
      .element() as HTMLElement;
    const aws = screen
      .getByRole("option", { name: "Amazon Web Services" })
      .element() as HTMLElement;
    const name = screen.getByText(LONG_LABEL).element() as HTMLElement;
    expect(getComputedStyle(name).textOverflow).toBe("ellipsis");
    expect(name.scrollWidth).toBeGreaterThan(name.clientWidth);
    expect(boxOf(long).width).toBe(boxOf(aws).width);
    expect(boxOf(long).height).toBe(boxOf(aws).height);
    // The Registry badge stays whole beside the cut name.
    await expect
      .element(screen.getByText("Registry", { exact: true }).last())
      .toBeVisible();
  });

  it("lays out the Registry placeholders like the providers they stand for", async () => {
    // When
    const screen = await render(
      <InWizard width={1200}>
        <Selector registryLoading />
      </InWizard>,
    );
    await screen.getByRole("tab", { name: "Registry" }).click();

    // Then
    const rows = Array.from(
      screen
        .getByRole("status", { name: "Loading Registry providers" })
        .element().children,
    ).map(boxOf);
    expect(rows[1].top).toBe(rows[0].top);
    expect(rows[1].left).toBeGreaterThan(rows[0].right);
  });
});

describe("provider selector header", () => {
  // Like the wizard's form column: a fixed-height box that scrolls.
  async function renderScrolled() {
    const screen = await render(
      <InWizard width={1200}>
        <div data-testid="scroller" style={{ height: 420, overflowY: "auto" }}>
          <Selector />
        </div>
      </InWizard>,
    );
    const scroller = screen.getByTestId("scroller").element() as HTMLElement;
    scroller.scrollTop = scroller.scrollHeight;
    await expect.poll(() => scroller.scrollTop).toBeGreaterThan(0);
    return { screen, scroller };
  }

  it("keeps the tabs and the search on top while the providers scroll", async () => {
    // When
    const { screen, scroller } = await renderScrolled();

    // Then
    const search = screen
      .getByRole("textbox", { name: "Search providers" })
      .element() as HTMLElement;
    const tabs = screen
      .getByRole("tablist", { name: "Provider source" })
      .element() as HTMLElement;
    const top = scroller.getBoundingClientRect().top;
    expect(tabs.getBoundingClientRect().top).toBeGreaterThanOrEqual(top);
    expect(search.getBoundingClientRect().bottom).toBeLessThan(top + 200);
    // Nothing scrolled under it shows through: the search is what is hit.
    const box = search.getBoundingClientRect();
    expect(
      document.elementFromPoint(box.left + 8, box.top + box.height / 2),
    ).toBe(search);
  });

  it("lands a provider scrolled back into view below the header", async () => {
    // Given: the first provider sits above the visible area.
    const { screen } = await renderScrolled();
    const header = document.querySelector(
      "[data-slot=provider-picker-header]",
    ) as HTMLElement;
    const first = screen
      .getByRole("option", { name: "Amazon Web Services" })
      .element() as HTMLElement;

    // When: edge-aligned scrolling, as keyboard navigation does.
    first.scrollIntoView({ block: "nearest" });

    // Then
    await expect
      .poll(() => first.getBoundingClientRect().top)
      .toBeGreaterThanOrEqual(header.getBoundingClientRect().bottom);
  });
});
