#!/usr/bin/env node
// Tour alignment check (syntactic). Extracts `data-tour-id` values from every
// `ui/lib/tours/*.tour.ts` and verifies a matching attribute exists under `ui/`,
// in either the JSX form (`data-tour-id="..."`) or the object-property form
// (`"data-tour-id": "..."`) used for dynamically-spread anchors. Two directions:
//   - Tour → DOM: fails on any tour `target` with no matching attribute.
//   - DOM → tour: warns on any `data-tour-id` not referenced by any tour
//     (does not fail — staged anchors during multi-PR rollouts are OK).
// Complements the semantic `prowler-tour` skill for CI/local runs without
// invoking Claude Code.
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join, dirname, relative, resolve } from "node:path";

const UI_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TOURS_DIR = join(UI_DIR, "lib", "tours");
const TOUR_FILE_SUFFIX = ".tour.ts";

const EXCLUDED_DIRS = new Set([
  "node_modules",
  ".next",
  "dist",
  "build",
  "coverage",
]);

async function readDirEntries(dir) {
  try {
    return await readdir(dir, { withFileTypes: true });
  } catch (err) {
    if (err && err.code === "ENOENT") return [];
    throw err;
  }
}

async function findTourFiles(dir) {
  const entries = await readDirEntries(dir);
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(TOUR_FILE_SUFFIX))
    .map((entry) => join(dir, entry.name));
}

const TOUR_ID_PATTERN = /\bid\s*:\s*["']([a-z0-9-]+)["']/m;
const TARGET_PATTERN = /\btarget\s*:\s*["']([a-z0-9-]+)["']/g;

async function parseTour(filePath) {
  const source = await readFile(filePath, "utf8");
  const idMatch = source.match(TOUR_ID_PATTERN);
  if (!idMatch) {
    throw new Error(
      `${relative(UI_DIR, filePath)}: cannot find tour 'id' — expected a literal like \`id: "attack-paths"\``,
    );
  }
  const tourId = idMatch[1];

  const targets = [];
  for (const match of source.matchAll(TARGET_PATTERN)) {
    targets.push(match[1]);
  }

  return {
    file: relative(UI_DIR, filePath),
    tourId,
    selectors: targets.map((target) => `${tourId}-${target}`),
  };
}

async function* walk(dir) {
  const entries = await readDirEntries(dir);
  for (const entry of entries) {
    if (EXCLUDED_DIRS.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walk(full);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

const ATTRIBUTE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx"];

async function collectAttributeValues() {
  const values = new Map();
  for await (const file of walk(UI_DIR)) {
    if (!ATTRIBUTE_EXTENSIONS.some((ext) => file.endsWith(ext))) continue;
    if (file.endsWith(TOUR_FILE_SUFFIX)) continue;
    const source = await readFile(file, "utf8");
    // Match both the JSX attribute form (`data-tour-id="x"`) and the
    // object-property form (`"data-tour-id": "x"`) used when an anchor is spread
    // dynamically — e.g. a table's per-row getRowAttributes returning the id.
    const pattern = /["']?data-tour-id["']?\s*[=:]\s*["']([a-z0-9-]+)["']/g;
    for (const match of source.matchAll(pattern)) {
      const value = match[1];
      const existing = values.get(value);
      if (existing) {
        existing.push(file);
      } else {
        values.set(value, [file]);
      }
    }
  }
  return values;
}

async function main() {
  const tourFiles = await findTourFiles(TOURS_DIR);
  if (tourFiles.length === 0) {
    console.log("No tour files under ui/lib/tours/ — nothing to check.");
    return;
  }

  const tours = await Promise.all(tourFiles.map(parseTour));
  const attrValues = await collectAttributeValues();

  const tourOrphans = [];
  for (const tour of tours) {
    for (const selector of tour.selectors) {
      if (!attrValues.has(selector)) {
        tourOrphans.push({ tour: tour.file, selector });
      }
    }
  }

  const referencedSelectors = new Set(tours.flatMap((t) => t.selectors));
  const domOrphans = [];
  for (const [value, files] of attrValues) {
    if (referencedSelectors.has(value)) continue;
    domOrphans.push({
      value,
      files: [...files].sort((a, b) => a.localeCompare(b)),
    });
  }
  domOrphans.sort((a, b) => a.value.localeCompare(b.value));
  tourOrphans.sort(
    (a, b) =>
      a.tour.localeCompare(b.tour) || a.selector.localeCompare(b.selector),
  );

  if (domOrphans.length > 0) {
    console.warn(
      `⚠ ${domOrphans.length} data-tour-id attribute(s) not referenced by any tour:`,
    );
    for (const orphan of domOrphans) {
      const locations = orphan.files
        .map((file) => relative(UI_DIR, file))
        .join(", ");
      console.warn(`  data-tour-id="${orphan.value}" — ${locations}`);
    }
    console.warn(
      "  Wire it into a tour step or remove the attribute (warning only, does not fail).\n",
    );
  }

  if (tourOrphans.length === 0) {
    const referenced = tours.reduce((sum, t) => sum + t.selectors.length, 0);
    console.log(
      `✓ Tour alignment OK — ${tours.length} tour(s), ${referenced} anchored step(s).`,
    );
    return;
  }

  console.error("✗ Tour alignment failed.\n");
  for (const orphan of tourOrphans) {
    console.error(
      `  ${orphan.tour} references data-tour-id="${orphan.selector}" but no element carries that attribute.`,
    );
  }
  console.error(
    "\nFix the drift before merging: add the attribute, fix the tour's `target`, or remove the orphan step.",
  );
  process.exit(1);
}

main().catch((err) => {
  console.error(err.stack || err.message);
  process.exit(1);
});
