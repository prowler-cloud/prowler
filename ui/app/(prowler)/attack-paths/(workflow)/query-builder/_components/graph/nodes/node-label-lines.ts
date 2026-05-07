const splitByMaxChars = (text: string, maxChars: number): string[] => {
  const words = text.trim().split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let currentLine = "";

  for (const word of words) {
    if (!currentLine) {
      currentLine = word;
      continue;
    }

    const nextLine = `${currentLine} ${word}`;
    if (nextLine.length <= maxChars) {
      currentLine = nextLine;
      continue;
    }

    lines.push(currentLine);
    currentLine = word;
  }

  if (currentLine) lines.push(currentLine);
  return lines;
};

const splitLongToken = (text: string, maxChars: number): string[] => {
  const lines: string[] = [];

  for (let index = 0; index < text.length; index += maxChars) {
    lines.push(text.slice(index, index + maxChars));
  }

  return lines;
};

export const getNodeLabelLines = (
  text: string,
  maxChars: number,
  maxLines: number,
): string[] => {
  if (!text.trim()) return [];

  const rawLines = text.includes(" ")
    ? splitByMaxChars(text, maxChars)
    : splitLongToken(text, maxChars);

  return rawLines.slice(0, maxLines);
};
