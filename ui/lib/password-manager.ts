// 1Password marks autofilled fields with data-com-onepassword-filled and paints
// a "filled" background highlight via styles injected outside the author cascade
// (web component / adopted sheet), so CSS overrides can't win. Removing the
// attribute makes its selector stop matching, restoring the design styles while
// leaving autofill itself untouched.
const ONEPASSWORD_FILLED_ATTR = "data-com-onepassword-filled";

/**
 * Ref callback for a form (or any container) that strips password-manager
 * fill highlights from descendant inputs.
 *
 * Returns a cleanup function so it works as a React 19 ref-callback cleanup —
 * no useEffect needed. Cheap by design: the observer is scoped to the container
 * and filtered to a single attribute, so the browser only invokes it when the
 * password manager toggles that attribute (once per fill), never per frame.
 *
 * @example
 * <form ref={stripPasswordManagerHighlight}>…</form>
 */
export const stripPasswordManagerHighlight = (
  container: HTMLElement | null,
): (() => void) | void => {
  if (!container) return;

  // removeAttribute on an element without the attribute is a no-op and emits no
  // mutation record, so re-firing the observer on our own removal can't loop.
  const strip = (element: Element) =>
    element.removeAttribute(ONEPASSWORD_FILLED_ATTR);

  container.querySelectorAll(`[${ONEPASSWORD_FILLED_ATTR}]`).forEach(strip);

  const observer = new MutationObserver((mutations) => {
    for (const { target } of mutations) {
      if (target instanceof Element) strip(target);
    }
  });

  observer.observe(container, {
    subtree: true,
    attributes: true,
    attributeFilter: [ONEPASSWORD_FILLED_ATTR],
  });

  return () => observer.disconnect();
};
