const splitLongToken = (text: string, maxChars: number): string[] => {
  const lines: string[] = [];

  for (let index = 0; index < text.length; index += maxChars) {
    lines.push(text.slice(index, index + maxChars));
  }

  return lines;
};

const splitByMaxChars = (text: string, maxChars: number): string[] => {
  const words = text.trim().split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let currentLine = "";

  for (const word of words) {
    const wordLines = splitLongToken(word, maxChars);

    for (const wordLine of wordLines) {
      if (!currentLine) {
        currentLine = wordLine;
        continue;
      }

      const nextLine = `${currentLine} ${wordLine}`;
      if (nextLine.length <= maxChars) {
        currentLine = nextLine;
        continue;
      }

      lines.push(currentLine);
      currentLine = wordLine;
    }
  }

  if (currentLine) lines.push(currentLine);
  return lines;
};

const withEllipsis = (line: string, maxChars: number): string => {
  if (maxChars <= 1) return "…";
  return `${line.slice(0, maxChars - 1)}…`;
};

export const getNodeLabelDisplay = (
  text: string,
  maxChars: number,
  maxLines: number,
): { lines: string[]; isTruncated: boolean } => {
  if (!text.trim()) return { lines: [], isTruncated: false };

  const rawLines = splitByMaxChars(text, maxChars);
  const isTruncated = rawLines.length > maxLines;
  const visibleLines = rawLines.slice(0, maxLines);

  if (isTruncated && visibleLines.length > 0) {
    visibleLines[visibleLines.length - 1] = withEllipsis(
      visibleLines[visibleLines.length - 1],
      maxChars,
    );
  }

  return { lines: visibleLines, isTruncated };
};
