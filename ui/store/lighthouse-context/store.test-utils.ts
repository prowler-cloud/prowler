import { useLighthouseContextStore } from "./store";

export function resetLighthouseContextStore(): void {
  useLighthouseContextStore.setState({
    contributions: {},
    focused: null,
    focusedOwnerToken: 0,
  });
}
