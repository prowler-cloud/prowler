/**
 * Turn a hyphenated framework key (e.g. ``CSA-CCM``) into a display title
 * (``CSA CCM``). Shared by the cross-provider card and header so both render
 * framework names identically.
 */
export const formatTitle = (title: string) => title.split("-").join(" ");
