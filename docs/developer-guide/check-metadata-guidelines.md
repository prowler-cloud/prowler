# Check Metadata Guidelines

## Introduction

This guide provides comprehensive guidelines for creating check metadata in Prowler. For basic information on check metadata structure, refer to the [check metadata](./checks.md#metadata-structure-for-prowler-checks) section.

## Check Title Guidelines

### Writing Guidelines

1. **Determine Resource Finding Scope (Singular vs. Plural)**:
   When determining whether to use singular or plural in the check title, examine the code for certain patterns. If the code contains a loop that generates an individual report for each resource, use the singular form. If the code produces a single report that covers all resources collectively, use the plural form. For organization- or account-wide checks, select the scope that best matches the breadth of the evaluation. Additionally, review the `status_extended` field messages in the code, as they often provide clues about whether the check is scoped to individual resources or to groups of resources.
   Analyze the detection code to determine if the check reports on individual resources or aggregated resources:
    - **Singular**: Use when the check creates one report per resource (e.g., "EC2 instance has IMDSv2 enforced", "S3 bucket does not allow public write access").
    - **Plural**: Use when the check creates one report for all resources together (e.g., "All EC2 instances have IMDSv2 enforced", "S3 buckets do not allow public write access").
2. **Describe the Compliant (*PASS*) State**:
   Always write the title to describe the **desired, compliant state** of the resources. The title should reflect what it looks like when the audited resource is following the check's requirements.
3. **Be Specific and Factual**:
   Include the exact secure configuration being verified. Avoid vague or generic terms like "properly configured".
4. **Avoid Redundant or Action Words**:
   Do not include verbs like "Check", "Verify", "Ensure", or "Monitor". The title is a declarative statement of the secure condition.
5. **Length Limit**:
   Keep the title under 150 characters.

### Common Mistakes to Avoid

- Starting with verbs like "Check", "Verify", "Ensure", "Make sure". Always start with the affected resource instead.
- Being too vague or generic (e.g., "Ensure security groups are properly configured", what does it mean? "properly configured" is not a clear description of the compliant state).
- Focusing on the non-compliant state instead of the compliant state.
- Using unclear scope and resource identification.

## Check Type Guidelines (AWS Only)

### AWS Security Hub Type Format

AWS Security Hub uses a three-part type taxonomy:

- **Namespace**: The top-level security domain.
- **Category**: The security control family or area.
- **Classifier**: The specific security concern (optional).

A partial path may be defined (e.g., `TTPs` or `TTPs/Defense Evasion` are valid).

### Selection Guidelines

1. **Be Specific**: Use the most specific classifier that accurately describes the check.
2. **Standard Compliance**: Consider if the check relates to specific compliance standards.
3. **Multiple Types**: You can specify multiple types if the check addresses multiple concerns.

## Description Guidelines

### Writing Guidelines

1. **Focus on the Finding**: All fields should address how the finding affects the security posture, rather than the control itself.
2. **Use Natural Language**: Write in simple, clear paragraphs with complete, grammatically correct sentences.
3. **Use Markdown Formatting**: Enhance readability with:
   - Use **bold** for emphasis on key security concepts.
   - Use *italic* for a secondary emphasis. Use it for clarifications, conditions, or optional notes. But don't abuse it.
   - Use `code` formatting for specific configuration values, or technical details. Don't use it for service names or common technical terms.
   - Use one or two line breaks (`\n` or `\n\n`) to separate distinct ideas.
   - Use bullet points (`-`) for listing multiple concepts or actions.
   - Use numbers for listing steps or sequential actions.
4. **Be Concise**: Maximum 400 characters (spaces count). Every word should add value.
5. **Explain What the Finding Means**: Focus on what the security control evaluates and what it means when it passes or fails, but without explicitly stating the pass or fail state.
6. **Be Technical but Clear**: Use appropriate technical terminology while remaining understandable.
7. **Avoid Risk Descriptions**: Do not describe potential risks, threats, or consequences.
8. **CheckTitle and Description can be the same**: If the check is very simple and the title is already clear, you can use the same text for the description.

### Common Mistakes to Avoid

- **Technical Implementation Details**: "The control loops through all instances and calls the describe_instances API...".
- **Vague Descriptions**: "This control verifies proper configuration of resources". What does it mean? "proper configuration" is not a clear description of the compliant state.
- **Risk Descriptions**: "This could lead to data breaches" or "This poses a security threat".
- **Starting with Verbs**: "Check if...", "Verify...", "Ensure...". Always start with the affected resource instead.
- **References to Pass/Fail States**: Avoid using words like "pass" or "fail".

## Risk Guidelines

### Writing Guidelines

1. **Explain the Cybersecurity Impact**: Focus on how the finding affects confidentiality, integrity, or availability (CIA triad). If the CIA triad does not apply, explain the risk in terms of the organization's business objectives.
2. **Be Specific About Threats**: Clearly state what could happen if this security control is not in place. What attacks or incidents become possible?
3. **Focus on Risk Context**: Explain the specific security implications of the finding, not just generic security risks.
4. **Use Markdown Formatting**: Enhance readability with markdown formatting:
   - Use **bold** for emphasis on key security concepts.
   - Use *italic* for a secondary emphasis. Use it for clarifications, conditions, or optional notes. But don't abuse it.
   - Use `code` formatting for specific configuration values, or technical details. Don't use it for service names or common technical terms.
   - Use one or two line breaks (`\n` or `\n\n`) to separate distinct ideas.
   - Use bullet points (`-`) for listing multiple concepts or actions.
   - Use numbers for listing steps or sequential actions.
5. **Be Concise**: Maximum 400 characters. Make every word count.

### Common Mistakes to Avoid

- **Generic Risks**: "This could lead to security issues" or "Regulatory compliance violations".
- **Technical Implementation Focus**: "The API call might fail and return incorrect results...".
- **Overly Broad Statements**: "This is a serious security risk that could impact everything".
- **Vague Threats**: "This could be exploited by threat actors" without explaining how.

## Recommendation Guidelines

### Writing Guidelines

1. **Provide Actionable Best Practice Guidance**: Explain what should be done to maintain security posture. Focus on preventive measures and proactive security practices.
2. **Be Principle-Based**: Reference established security principles (least privilege, defense in depth, zero trust, separation of duties) where applicable.
3. **Focus on Prevention**: Explain best practices that prevent the security issue from occurring, not just detection or remediation.
4. **Use Markdown Formatting**: Enhance readability with markdown formatting:
   - Use **bold** for emphasis on key security concepts.
   - Use *italic* for a secondary emphasis. Use it for clarifications, conditions, or optional notes. But don't abuse it.
   - Use `code` formatting for specific configuration values, or technical details. Don't use it for service names or common technical terms.
   - Use one or two line breaks (`\n` or `\n\n`) to separate distinct ideas.
   - Use bullet points (`-`) for listing multiple concepts or actions.
   - Use numbers for listing steps or sequential actions.
5. **Be Concise**: Maximum 400 characters.

### Common Mistakes to Avoid

- **Specific Remediation Steps**: "1. Go to the console\n2. Click on settings..." - Focus on principles, not click-by-click instructions.
- **Implementation Details**: "Configure the JSON policy with the following IAM actions..." - Explain what to achieve, not how.
- **Vague Guidance**: "Follow security best practices..." without explaining what those practices are.
- **Resource-Specific Recommendations**: "Enable MFA on user john.doe@example.com" - Keep it general.
- **Missing Context**: Not explaining why the best practice is important for security.

### Good Examples

- *"Avoid exposing sensitive resources directly to the Internet; configure access controls to limit exposure."*
- *"Apply the principle of least privilege when assigning permissions to users and services."*
- *"Regularly review and update your security configurations to align with current best practices."*

## Remediation Code Guidelines

### Critical Requirement

The **fundamental principle** is to focus on the **specific change** that converts the finding from non-compliant to compliant.

Also is important to keep all code examples as short as possible, including the essential code to fix the issue. Remove any extra configuration, optional parameters, or nice-to-have settings and add comments to explain the code when possible.

### Common Guidelines for All Code Fields

1. **Be Minimal**: Keep code blocks as short as possible - only include what is absolutely necessary.
2. **Focus on the Fix**: Remove any extra configuration, optional parameters, or nice-to-have settings.
3. **Be Accurate**: Ensure all commands and code are syntactically correct.
4. **Use Markdown Formatting**: Format code properly using code blocks and appropriate syntax highlighting.
5. **Follow Best Practices**: Use the most secure and recommended approaches for each platform.

### CLI Guidelines

- Only provide a single command that directly changes the finding from fail to pass.
- The command must be executable as-is and resolve the security issue completely.
- Use proper command syntax for the provider (AWS CLI, Azure CLI, gcloud, kubectl, etc.).
- Do not use markdown formatting or code blocks - just the raw command.
- Do not include multiple commands, comments, or explanations.
- If the issue cannot be resolved with a single command, leave this field empty.

### Native IaC Guidelines

- **Keep It Minimal**: Only include the specific resource/configuration that fixes the security issue.
- Format as markdown code blocks with proper syntax highlighting.
- Include only the required properties to fix the issue.
- Add comments indicating the critical line(s) that remediate the check.
- Use `example_resource` as the generic name for all resources and IDs.

### Terraform Guidelines

- **Keep It Minimal**: Only include the specific resource/configuration that fixes the security issue.
- Provide valid HCL (HashiCorp Configuration Language) code with an example of a compliant configuration.
- Use the latest Terraform syntax and provider versions.
- Include only the required arguments to fix the issue - skip optional parameters.
- Format as markdown code blocks with `hcl` syntax highlighting.
- Add comments indicating the critical line(s) that remediate the check.
- Use `example_resource` as the generic name for all resources and IDs.
- Skip provider requirements unless critical for the fix.

### Other (Manual Steps) Guidelines

- **Keep It Minimal**: Only include the exact steps needed to fix the security issue.
- Provide step-by-step instructions for manual remediation through web interfaces.
- Use numbered lists for sequential steps.
- Be specific about menu locations, button names, and settings.
- Skip optional configurations or nice-to-have settings.
- Format using markdown for better readability.

## Categories Guidelines

### Selection Guidelines

1. **Be Specific**: Only select categories that directly relate to what the automated control evaluates.
2. **Primary Focus**: Consider the primary security concern the automated control addresses.
3. **Avoid Over-Categorization**: Do not select categories just because they are tangentially related.

### Available Categories

| Category                | Definition                                                                                                                                                                                                                                 |
|-------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| encryption              | Ensures data is encrypted in transit and/or at rest, including key management practices                                                                                                   |
| internet-exposed        | Checks that limit or flag public access to services, APIs, or assets from the Internet                                                                                                              |
| logging                 | Ensures appropriate logging of events, activities, and system interactions for traceability                                                                                                       |
| secrets                 | Manages and protects credentials, API keys, tokens, and other sensitive information                                                                                                               |
| resilience              | Ensures systems can maintain availability and recover from disruptions, failures, or degradation. Includes redundancy, fault-tolerance, auto-scaling, backup, disaster recovery, and failover strategies |
| threat-detection        | Identifies suspicious activity or behaviors using IDS, malware scanning, or anomaly detection                                                                                                      |
| trust-boundaries        | Enforces isolation or segmentation between different trust levels (e.g., VPCs, tenants, network zones)                                                                                            |
| vulnerabilities         | Detects or remediates known software, infrastructure, or config vulnerabilities (e.g., CVEs)                                                                                                      |
| cluster-security        | Secures Kubernetes cluster components such as API server, etcd, and role-based access                                                                                                             |
| container-security      | Ensures container images and runtimes follow security best practices                                                                                        |
| node-security           | Secures nodes running containers or services                                                                                                        |
| gen-ai                  | Checks related to safe and secure use of generative AI services or models                                                                                                                        |
| ci-cd                   | Ensures secure configurations in CI/CD pipelines                                                                                                         |
| identity-access         | Governs user and service identities, including least privilege, MFA, and permission boundaries                                                                                                    |
| email-security          | Ensures detection and protection against phishing, spam, spoofing, etc.                                                                                                                            |
| forensics-ready         | Ensures systems are instrumented to support post-incident investigations. Any digital trace or evidence (logs, volume snapshots, memory dumps, network captures, etc.) preserved immutably and accompanied by integrity guarantees, which can be used in a forensic analysis |
| software-supply-chain   | Detects or prevents tampering, unauthorized packages, or third-party risks in software supply chain                                                                                               |
| e3                      | M365-specific controls enabled by or dependent on an E3 license (e.g., baseline security policies, conditional access)                                                                            |
| e5                      | M365-specific controls enabled by or dependent on an E5 license (e.g., advanced threat protection, audit, DLP, and eDiscovery)                                                                    |
