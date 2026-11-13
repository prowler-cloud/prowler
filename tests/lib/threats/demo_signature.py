"""A fictional emerging threat the SDK tests run against.

Prowler ships no threat signatures of its own; scans receive them through the
``threat_signatures`` configuration key. The tests therefore bring their own,
modelled on a real-world shape: an SSH authentication bypass on the minimal
("tiny") images of a made-up distribution, DemoOS, fixed per release branch.
"""

import yaml

DEMO_PUBLISHER = "111122223333"

DEMO_SSH_BYPASS = yaml.safe_load(r"""
id: demo-ssh-bypass
title: Demo SSH authentication bypass on DemoOS
cves: [CVE-2026-0101]
severity: critical
published: 2026-01-15
summary: A demo SSH bypass on DemoOS tiny images.
references:
  - https://example.com/advisories/demo-ssh-bypass
images:
  - cloud: aws
    publishers: ["111122223333"]
    name_regex: '^demoos-(?P<version>\d+\.\d+\.\d+)-(x86_64|aarch64)-\w+-tiny-r\d+$'
    versions: &affected
      - {min: "3.18.11", max: "3.21.9"}
      - {min: "3.22.0", max: "3.22.7"}
      - {min: "3.23.0", max: "3.23.7"}
      - {min: "3.24.0", max: "3.24.3"}
    examples:
      matches: [demoos-3.22.2-x86_64-uefi-tiny-r0, demoos-3.24.3-aarch64-uefi-tiny-r0]
      misses: [demoos-3.22.8-x86_64-uefi-tiny-r0, demoos-3.22.2-x86_64-uefi-cloudinit-r0]
  - cloud: azure
    name_regex: 'demoos-(?P<version>\d+\.\d+\.\d+)-(x86_64|aarch64)-\w+-tiny'
    versions: *affected
    examples:
      matches: [demoos-3.21.2-x86_64-uefi-tiny]
      misses: [demoos-3.22.8-x86_64-uefi-tiny]
  - cloud: gcp
    name_regex: 'demoos-(?P<version>\d+[.-]\d+[.-]\d+)-(x86-64|x86_64|aarch64)-\w+-tiny'
    versions: *affected
    examples:
      matches: [demoos-3-20-3-x86-64-bios-tiny-r0]
      misses: [demoos-3-24-4-x86-64-uefi-tiny-r0]
exposure: {protocol: tcp, ports: [22]}
credential_required: false
impact: A root shell through the image's default user.
mitigations: [password_authentication_disabled, port_not_exposed]
remediation: Restrict TCP 22, then upgrade the SSH server.
""")


def with_demo(audit_config=None) -> dict:
    """An audit config carrying the demo threat plus any signatures it supplies."""
    audit_config = dict(audit_config or {})
    audit_config["threat_signatures"] = [
        DEMO_SSH_BYPASS,
        *(audit_config.get("threat_signatures") or []),
    ]
    return audit_config
