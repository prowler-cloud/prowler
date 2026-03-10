const fs = require('fs');
const path = require('path');

function readJSON(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function getInstalledVersion(pkgName) {
  try {
    const parts = pkgName.split('/');
    const pkgPath = path.join('node_modules', ...parts, 'package.json');
    const meta = readJSON(pkgPath);
    return meta.version;
  } catch (e) {
    return null;
  }
}

function collect(sectionName, obj) {
  if (!obj) return [];
  return Object.entries(obj).map(([name, declared]) => {
    const installed = getInstalledVersion(name);
    return {
      section: sectionName,
      name,
      from: declared,
      to: installed || null,
      strategy: 'installed',
    };
  });
}

function main() {
  // If node_modules is missing, skip to avoid generating noisy diffs
  if (!fs.existsSync('node_modules')) {
    console.log('Skip: node_modules not found. Run npm install first.');
    return;
  }

  const pkg = readJSON('package.json');
  const entries = [
    ...collect('dependencies', pkg.dependencies),
    ...collect('devDependencies', pkg.devDependencies),
  ];

  // Stable sort by section then name
  entries.sort((a, b) =>
    a.section === b.section ? a.name.localeCompare(b.name) : a.section.localeCompare(b.section)
  );

  const outPath = path.join(process.cwd(), 'dependency-log.json');
  // Merge with previous to preserve generatedAt when unchanged
  let prevMap = new Map();
  if (fs.existsSync(outPath)) {
    try {
      const prev = JSON.parse(fs.readFileSync(outPath, 'utf8'));
      for (const e of prev) {
        prevMap.set(`${e.section}::${e.name}`, e);
      }
    } catch {}
  }

  const now = new Date().toISOString();
  const merged = entries.map((e) => {
    const key = `${e.section}::${e.name}`;
    const prev = prevMap.get(key);
    if (!prev) {
      // New entry: keep declared as from
      return { ...e, generatedAt: now };
    }

    // If installed version changed, set from to previous installed version
    if (prev.to !== e.to) {
      return { ...e, from: prev.to, generatedAt: now };
    }

    // Otherwise preserve previous 'from' and timestamp
    return { ...e, from: prev.from, generatedAt: prev.generatedAt || now };
  });

  const nextContent = JSON.stringify(merged, null, 2) + '\n';
  if (fs.existsSync(outPath)) {
    try {
      const prevContent = fs.readFileSync(outPath, 'utf8');
      if (prevContent === nextContent) {
        console.log(`No changes for ${outPath} (entries: ${entries.length}).`);
        return;
      }
    } catch {}
  }
  fs.writeFileSync(outPath, nextContent);
  console.log(`Updated ${outPath} with ${entries.length} entries.`);
}

main();
