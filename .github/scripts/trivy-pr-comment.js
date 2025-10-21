const fs = require('fs');
const report = JSON.parse(fs.readFileSync('trivy-report.json', 'utf-8'));

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

const imageName = process.env.IMAGE_NAME || 'prowler-api';
const sha = process.env.GITHUB_SHA?.substring(0, 7) || 'unknown';

let comment = '## 🔒 Container Security Scan\n\n';
comment += `**Image:** \`${imageName}:${sha}\`\n\n`;

if (vulnCount === 0) {
    comment += '### ✅ No Vulnerabilities Detected\n\n';
    comment += 'The container image passed all security checks. No known CVEs were found.\n';
} else {
    comment += '### 📊 Vulnerability Summary\n\n';
    comment += '| Severity | Count |\n';
    comment += '|----------|-------|\n';
    comment += `| 🔴 Critical | **${vulnsByType.CRITICAL}** |\n`;
    comment += `| 🟠 High | **${vulnsByType.HIGH}** |\n`;
    comment += `| 🟡 Medium | **${vulnsByType.MEDIUM}** |\n`;
    comment += `| 🔵 Low | ${vulnsByType.LOW} |\n`;
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
comment += `- [View in Security tab](https://github.com/${process.env.GITHUB_REPOSITORY}/security/code-scanning)\n`;
comment += '- [Download full report](../../actions/runs/' + process.env.GITHUB_RUN_ID + ') (see artifacts)\n';
comment += '- Scanned with [Trivy](https://github.com/aquasecurity/trivy)\n';

return comment;
