# Security

## Reporting Vulnerabilities

At Prowler, we consider the security of our open source software and systems a top priority. But no matter how much effort we put into system security, there can still be vulnerabilities present.

If you discover a vulnerability, we would like to know about it so we can take steps to address it as quickly as possible. We would like to ask you to help us better protect our users, our clients and our systems.

When reporting vulnerabilities, please consider (1) attack scenario / exploitability, and (2) the security impact of the bug. The following issues are considered out of scope:

- Social engineering support or attacks requiring social engineering.
- Clickjacking on pages with no sensitive actions.
- Cross-Site Request Forgery (CSRF) on unauthenticated forms or forms with no sensitive actions.
- Attacks requiring Man-In-The-Middle (MITM) or physical access to a user's device.
- Previously known vulnerable libraries without a working Proof of Concept (PoC).
- Comma Separated Values (CSV) injection without demonstrating a vulnerability.
- Missing best practices in SSL/TLS configuration.
- Any activity that could lead to the disruption of service (DoS).
- Rate limiting or brute force issues on non-authentication endpoints.
- Missing best practices in Content Security Policy (CSP).
- Missing HttpOnly or Secure flags on cookies.
- Configuration of or missing security headers.
- Missing email best practices, such as invalid, incomplete, or missing SPF/DKIM/DMARC records.
- Vulnerabilities only affecting users of outdated or unpatched browsers (less than two stable versions behind).
- Software version disclosure, banner identification issues, or descriptive error messages.
- Tabnabbing.
- Issues that require unlikely user interaction.
- Improper logout functionality and improper session timeout.
- CORS misconfiguration without an exploitation scenario.
- Broken link hijacking.
- Automated scanning results (e.g., sqlmap, Burp active scanner) that have not been manually verified.
- Content spoofing and text injection issues without a clear attack vector.
- Email spoofing without exploiting security flaws.
- Dead links or broken links.
- User enumeration.

Testing guidelines:
- Do not run automated scanners on other customer projects. Running automated scanners can run up costs for our users. Aggressively configured scanners might inadvertently disrupt services, exploit vulnerabilities, lead to system instability or breaches and violate Terms of Service from our upstream providers. Our own security systems won't be able to distinguish hostile reconnaissance from whitehat research. If you wish to run an automated scanner, notify us at support@prowler.com and only run it on your own Prowler app project. Do NOT attack Prowler in usage of other customers.
- Do not take advantage of the vulnerability or problem you have discovered, for example by downloading more data than necessary to demonstrate the vulnerability or deleting or modifying other people's data.

Reporting guidelines:
- File a report through our Support Desk at https://support.prowler.com
- If it is about a lack of a security functionality, please file a feature request instead at https://github.com/prowler-cloud/prowler/issues
- Do provide sufficient information to reproduce the problem, so we will be able to resolve it as quickly as possible.
- If you have further questions and want direct interaction with the Prowler team, please contact us at via our Community Slack at goto.prowler.com/slack.

Disclosure guidelines:
- In order to protect our users and customers, do not reveal the problem to others until we have researched, addressed and informed our affected customers.
- If you want to publicly share your research about Prowler at a conference, in a blog or any other public forum, you should share a draft with us for review and approval at least 30 days prior to the publication date. Please note that the following should not be included:
    - Data regarding any Prowler user or customer projects.
    - Prowler customers' data.
    - Information about Prowler employees, contractors or partners.

What we promise:
- We will respond to your report within 5 business days with our evaluation of the report and an expected resolution date.
- If you have followed the instructions above, we will not take any legal action against you in regard to the report.
- We will handle your report with strict confidentiality, and not pass on your personal details to third parties without your permission.
- We will keep you informed of the progress towards resolving the problem.
- In the public information concerning the problem reported, we will give your name as the discoverer of the problem (unless you desire otherwise).

We strive to resolve all problems as quickly as possible, and we would like to play an active role in the ultimate publication on the problem after it is resolved.

---

For more information about our security policies, please refer to our [Security](https://docs.prowler.com/security) section in our documentation.
