import type { PopoverDOM } from "driver.js";
import { XIcon } from "lucide-react";
import { flushSync } from "react-dom";
import { createRoot, type Root } from "react-dom/client";

import {
  Button,
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
  Progress,
} from "@/components/shadcn";

interface TourPopoverProps {
  title: string;
  description: string;
  progressText: string;
  progressValue: number;
  previousLabel: string;
  nextLabel: string;
  closeLabel: string;
  showPrevious: boolean;
  showNext: boolean;
  showClose: boolean;
  previousDisabled: boolean;
  onPrevious: () => void;
  onNext: () => void;
  onClose: () => void;
}

let activeRoot: Root | null = null;
let activeWrapper: HTMLElement | null = null;

function isDisplayed(element: HTMLElement): boolean {
  return element.style.display !== "none";
}

function parseProgressValue(progressText: string): number {
  const match = progressText.match(/(\d+)\D+(\d+)/);
  if (!match) return 0;

  const current = Number(match[1]);
  const total = Number(match[2]);
  if (total <= 0) return 0;

  return Math.min(100, Math.max(0, (current / total) * 100));
}

function getText(element: HTMLElement, fallback: string): string {
  const text = element.textContent?.trim();
  return text && text.length > 0 ? text : fallback;
}

function hideDriverPopoverDom(popover: PopoverDOM) {
  popover.title.hidden = true;
  popover.description.hidden = true;
  popover.footer.hidden = true;
  popover.closeButton.hidden = true;
  popover.arrow.hidden = true;
}

function getOrCreateMount(popover: PopoverDOM): HTMLElement {
  const existing = popover.wrapper.querySelector<HTMLElement>(
    "[data-tour-popover-root]",
  );
  if (existing) {
    existing.style.width = "100%";
    return existing;
  }

  const mount = document.createElement("div");
  mount.dataset.tourPopoverRoot = "";
  mount.style.width = "100%";
  popover.wrapper.appendChild(mount);
  return mount;
}

function TourPopover({
  title,
  description,
  progressText,
  progressValue,
  previousLabel,
  nextLabel,
  closeLabel,
  showPrevious,
  showNext,
  showClose,
  previousDisabled,
  onPrevious,
  onNext,
  onClose,
}: TourPopoverProps) {
  return (
    <Card variant="inner" className="gap-0 shadow-lg">
      <CardHeader className="mb-4">
        <CardTitle className="text-base leading-snug">{title}</CardTitle>
        {showClose ? (
          <CardAction>
            <Button
              aria-label={closeLabel}
              size="icon-xs"
              variant="bare"
              onClick={onClose}
            >
              <XIcon aria-hidden="true" />
            </Button>
          </CardAction>
        ) : null}
        {description ? (
          <CardDescription className="mt-2 text-xs leading-relaxed">
            {description}
          </CardDescription>
        ) : null}
      </CardHeader>
      <CardContent className="mt-2">
        {progressText ? (
          <>
            <CardDescription className="mt-2 text-xs leading-relaxed">
              {progressText}
            </CardDescription>
            <Progress value={progressValue} />
          </>
        ) : null}
      </CardContent>
      <CardFooter className="mt-4 justify-end gap-2 px-0">
        {showPrevious ? (
          <Button
            disabled={previousDisabled}
            size="sm"
            variant="ghost"
            onClick={onPrevious}
          >
            {previousLabel}
          </Button>
        ) : null}
        {showNext ? (
          <Button size="sm" onClick={onNext}>
            {nextLabel}
          </Button>
        ) : null}
      </CardFooter>
    </Card>
  );
}

export function unmountActiveTourPopover() {
  activeRoot?.unmount();
  activeRoot = null;
  activeWrapper = null;
}

export function renderTourPopover(popover: PopoverDOM) {
  if (activeWrapper !== popover.wrapper) {
    unmountActiveTourPopover();
  }

  hideDriverPopoverDom(popover);

  const mount = getOrCreateMount(popover);
  activeRoot = activeRoot ?? createRoot(mount);
  activeWrapper = popover.wrapper;

  const progressText = isDisplayed(popover.progress)
    ? getText(popover.progress, "")
    : "";

  flushSync(() => {
    activeRoot?.render(
      <TourPopover
        title={getText(popover.title, "")}
        description={getText(popover.description, "")}
        progressText={progressText}
        progressValue={parseProgressValue(progressText)}
        previousLabel={getText(popover.previousButton, "Back")}
        nextLabel={getText(popover.nextButton, "Next")}
        closeLabel={popover.closeButton.getAttribute("aria-label") ?? "Close"}
        showPrevious={isDisplayed(popover.previousButton)}
        showNext={isDisplayed(popover.nextButton)}
        showClose={isDisplayed(popover.closeButton)}
        previousDisabled={popover.previousButton.disabled}
        onPrevious={() => {
          if (!popover.previousButton.disabled) popover.previousButton.click();
        }}
        onNext={() => popover.nextButton.click()}
        onClose={() => popover.closeButton.click()}
      />,
    );
  });
}
