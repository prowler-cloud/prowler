const fs = require('fs');

// Configuration from environment variables
const REPORT_FILE = process.env.TRIVY_REPORT_FILE || 'trivy-report.json';
const IMAGE_NAME = process.env.IMAGE_NAME || 'container-image';
const GITHUB_SHA = process.env.GITHUB_SHA || 'unknown';
const GITHUB_REPOSITORY = process.env.GITHUB_REPOSITORY || '';
const GITHUB_RUN_ID = process.env.GITHUB_RUN_ID || '';
const SEVERITY = process.env.SEVERITY || 'CRITICAL,HIGH,MEDIUM,LOW';

// Parse severities to scan
const scannedSeverities = SEVERITY.split(',').map(s => s.trim());

// Read and parse the Trivy report
const report = JSON.parse(fs.readFileSync(REPORT_FILE, 'utf-8'));

let vulnCount = 0;
let vulnsByType = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
let affectedPackages = new Set();

if (report.Results && Array.isArray(report.Results)) {
    for (const result of report.Results) {
        if (result.Vulnerabilities && Array.isArray(result.Vulnerabilities)) {
            for (const vuln of result.Vulnerabilities) {
                vulnCount++;
                if (vulnsByType[vuln.Severity] !== undefined) {
                    vulnsByType[vuln.Severity]++;
                }
                if (vuln.PkgName) {
                    affectedPackages.add(vuln.PkgName);
                }
            }
        }
    }
}

const shortSha = GITHUB_SHA.substring(0, 7);
const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

// Severity icons and labels
const severityConfig = {
    CRITICAL: { icon: '🔴', label: 'Critical' },
    HIGH: { icon: '🟠', label: 'High' },
    MEDIUM: { icon: '🟡', label: 'Medium' },
    LOW: { icon: '🔵', label: 'Low' }
};

let comment = '## 🔒 Container Security Scan\n\n';
comment += `**Image:** \`${IMAGE_NAME}:${shortSha}\`\n`;
comment += `**Last scan:** ${timestamp}\n\n`;

if (vulnCount === 0) {
    comment += '### ✅ No Vulnerabilities Detected\n\n';
    comment += 'The container image passed all security checks. No known CVEs were found.\n';
} else {
    comment += '### 📊 Vulnerability Summary\n\n';
    comment += '| Severity | Count |\n';
    comment += '|----------|-------|\n';

    // Only show severities that were scanned
    for (const severity of scannedSeverities) {
        const config = severityConfig[severity];
        const count = vulnsByType[severity] || 0;
        const isBold = (severity === 'CRITICAL' || severity === 'HIGH') && count > 0;
        const countDisplay = isBold ? `**${count}**` : count;
        comment += `| ${config.icon} ${config.label} | ${countDisplay} |\n`;
    }

    comment += `| **Total** | **${vulnCount}** |\n\n`;

    if (affectedPackages.size > 0) {
        comment += `**${affectedPackages.size}** package(s) affected\n\n`;
    }

    if (vulnsByType.CRITICAL > 0) {
        comment += '### ⚠️ Action Required\n\n';
        comment += '**Critical severity vulnerabilities detected.** These should be addressed before merging:\n';
        comment += '- Review the detailed scan results\n';
        comment += '- Update affected packages to patched versions\n';
        comment += '- Consider using a different base image if updates are unavailable\n\n';
    } else if (vulnsByType.HIGH > 0) {
        comment += '### ⚠️ Attention Needed\n\n';
        comment += '**High severity vulnerabilities found.** Please review and plan remediation:\n';
        comment += '- Assess the risk and exploitability\n';
        comment += '- Prioritize updates in the next maintenance cycle\n\n';
    } else {
        comment += '### ℹ️ Review Recommended\n\n';
        comment += 'Medium/Low severity vulnerabilities found. Consider addressing during regular maintenance.\n\n';
    }
}

comment += '---\n';
comment += '📋 **Resources:**\n';

if (GITHUB_REPOSITORY && GITHUB_RUN_ID) {
    comment += `- [Download full report](https://github.com/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}) (see artifacts)\n`;
}

comment += '- [View in Security tab](https://github.com/' + (GITHUB_REPOSITORY || 'repository') + '/security/code-scanning)\n';
comment += '- Scanned with [Trivy](https://github.com/aquasecurity/trivy)\n';

module.exports = comment;
