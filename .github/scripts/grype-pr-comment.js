const fs = require('fs');

// Configuration from environment variables
const REPORT_FILE = process.env.GRYPE_REPORT_FILE || 'grype-report.json';
const IMAGE_NAME = process.env.IMAGE_NAME || 'container-image';
const GITHUB_SHA = process.env.GITHUB_SHA || 'unknown';
const GITHUB_REPOSITORY = process.env.GITHUB_REPOSITORY || '';
const GITHUB_RUN_ID = process.env.GITHUB_RUN_ID || '';
const CUTOFF = process.env.CUTOFF || 'high';

// A cutoff of 'critical' blocks only on critical; anything else blocks on high and above
const blocking = CUTOFF === 'critical' ? ['Critical'] : ['Critical', 'High'];

const report = JSON.parse(fs.readFileSync(REPORT_FILE, 'utf-8'));
const matches = Array.isArray(report.matches) ? report.matches : [];
const ignored = Array.isArray(report.ignoredMatches) ? report.ignoredMatches : [];

const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 };
const blockers = new Map();

for (const match of matches) {
    const severity = match.vulnerability.severity;
    if (counts[severity] !== undefined) {
        counts[severity]++;
    }
    if (blocking.includes(severity)) {
        const artifact = match.artifact;
        const fixedIn = (match.vulnerability.fix && match.vulnerability.fix.versions || []).join(', ');
        // Same CVE can match several install paths of one package; collapse them
        blockers.set(`${match.vulnerability.id}|${artifact.name}`, {
            id: match.vulnerability.id,
            severity,
            name: artifact.name,
            version: artifact.version,
            fixedIn
        });
    }
}

const ignoredBlocking = ignored.filter(m => blocking.includes(m.vulnerability.severity)).length;
const shortSha = GITHUB_SHA.substring(0, 7);
const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

const severityConfig = {
    Critical: { icon: '🔴', label: 'Critical' },
    High: { icon: '🟠', label: 'High' },
    Medium: { icon: '🟡', label: 'Medium' },
    Low: { icon: '🔵', label: 'Low' }
};

let comment = '## 🔎 Container Security Scan (Grype)\n\n';
comment += `**Image:** \`${IMAGE_NAME}:${shortSha}\`\n`;
comment += `**Last scan:** ${timestamp}\n\n`;

if (blockers.size === 0) {
    comment += '### ✅ Nothing Blocking\n\n';
    comment += `No findings at **${blocking.join(' or ').toLowerCase()}** severity.\n`;
} else {
    comment += `### ⚠️ ${blockers.size} Finding(s) Blocking This PR\n\n`;
    comment += '| Severity | CVE | Package | Installed | Fixed in |\n';
    comment += '|---|---|---|---|---|\n';

    const order = { Critical: 0, High: 1 };
    const rows = [...blockers.values()].sort((a, b) =>
        (order[a.severity] - order[b.severity]) || a.name.localeCompare(b.name));

    for (const row of rows) {
        const config = severityConfig[row.severity];
        comment += `| ${config.icon} ${config.label} | \`${row.id}\` | \`${row.name}\` | ${row.version} | ${row.fixedIn || '—'} |\n`;
    }

    comment += '\n**What to do:**\n';
    comment += '- Upgrade the package to the version in the "Fixed in" column.\n';
    comment += '- If it is pinned by another dependency, or the fix is otherwise out of reach, add it to `.grype.yaml` **with the reason**.\n';
    comment += '- Findings with no published fix never appear here: the scan runs with `only-fixed`, so it reports only what can actually be acted on.\n';
}

const otherCounts = Object.entries(counts)
    .filter(([severity, count]) => !blocking.includes(severity) && count > 0)
    .map(([severity, count]) => `${severity.toLowerCase()}: ${count}`);

if (otherCounts.length > 0) {
    comment += `\nNot blocking at this cutoff — ${otherCounts.join(', ')}.\n`;
}

if (ignoredBlocking > 0) {
    comment += `\n${ignoredBlocking} finding(s) excluded by \`.grype.yaml\`, each with a documented reason.\n`;
}

comment += '\n---\n';
comment += '📋 **Resources:**\n';

if (GITHUB_REPOSITORY && GITHUB_RUN_ID) {
    comment += `- [Download full report](https://github.com/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}) (see artifacts)\n`;
}

comment += '- [View in Security tab](https://github.com/' + (GITHUB_REPOSITORY || 'repository') + '/security/code-scanning)\n';
comment += '- Scanned with [Grype](https://github.com/anchore/grype), alongside Trivy\n';

module.exports = comment;
