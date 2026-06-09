"""Network egress whitelist generator — Layer 4 of defense in depth.

Generates iptables rules or AWS Security Group configurations from the
engagement scope. Even if all application-layer checks fail, out-of-scope
traffic is dropped at the network level.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass

from diana.engagement.audit import AuditLogger
from diana.engagement.models import EngagementConfig


@dataclass
class EgressRule:
    destination_ip: str
    port: int
    protocol: str = "tcp"
    comment: str = ""


class NetGuard:
    """Generates and optionally applies network-level egress restrictions."""

    # Chain name for diana rules — avoids conflicts with system iptables
    CHAIN_NAME = "DIANA_EGRESS"

    def __init__(self, config: EngagementConfig, audit: AuditLogger):
        self.config = config
        self.audit = audit

    def generate_egress_rules(
        self, resolved_ips: dict[str, list[str]]
    ) -> list[EgressRule]:
        """Generate egress rules from engagement scope + resolved IPs."""
        rules: list[EgressRule] = []
        ports_by_domain = self.config.get_whitelisted_ports()

        for domain, ips in resolved_ips.items():
            ports = ports_by_domain.get(domain, [443])
            for ip in ips:
                for port in ports:
                    rules.append(EgressRule(
                        destination_ip=ip,
                        port=port,
                        comment=f"{domain}:{port}",
                    ))

        # Always allow Bedrock endpoint (HTTPS)
        rules.append(EgressRule(
            destination_ip="0.0.0.0/0",
            port=443,
            comment="bedrock-api-https",
        ))

        # Always allow DNS (for initial resolution)
        rules.append(EgressRule(
            destination_ip="0.0.0.0/0",
            port=53,
            protocol="udp",
            comment="dns-resolution",
        ))

        return rules

    def generate_iptables_script(
        self, resolved_ips: dict[str, list[str]]
    ) -> str:
        """Generate an iptables script that restricts egress to in-scope targets only."""
        rules = self.generate_egress_rules(resolved_ips)

        lines = [
            "#!/bin/bash",
            "set -euo pipefail",
            "",
            f"# Diana engagement egress rules — {self.config.engagement.id}",
            f"# Generated for engagement: {self.config.engagement.client}",
            f"# Targets: {', '.join(self.config.get_whitelisted_domains())}",
            "",
            "# Create diana chain",
            f"iptables -N {self.CHAIN_NAME} 2>/dev/null || iptables -F {self.CHAIN_NAME}",
            "",
            "# Allow established connections",
            f"iptables -A {self.CHAIN_NAME} -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "",
            "# Allow loopback",
            f"iptables -A {self.CHAIN_NAME} -o lo -j ACCEPT",
            "",
            "# Allow in-scope targets",
        ]

        for rule in rules:
            comment = rule.comment.replace(" ", "_")[:255]
            lines.append(
                f"iptables -A {self.CHAIN_NAME} -p {rule.protocol} "
                f"-d {rule.destination_ip} --dport {rule.port} "
                f'-m comment --comment "{comment}" -j ACCEPT'
            )

        lines.extend([
            "",
            "# DENY everything else",
            f"iptables -A {self.CHAIN_NAME} -j DROP",
            "",
            "# Attach to OUTPUT chain",
            f"iptables -I OUTPUT -j {self.CHAIN_NAME}",
            "",
            f'echo "Diana egress rules applied — {len(rules)} rules loaded"',
        ])

        return "\n".join(lines)

    def generate_security_group_rules(
        self, resolved_ips: dict[str, list[str]]
    ) -> list[dict]:
        """Generate AWS Security Group egress rules as JSON-compatible dicts."""
        rules = self.generate_egress_rules(resolved_ips)
        sg_rules = []

        for rule in rules:
            sg_rules.append({
                "IpProtocol": rule.protocol,
                "FromPort": rule.port,
                "ToPort": rule.port,
                "IpRanges": [
                    {
                        "CidrIp": (
                            rule.destination_ip
                            if "/" in rule.destination_ip
                            else f"{rule.destination_ip}/32"
                        ),
                        "Description": rule.comment,
                    }
                ],
            })

        return sg_rules

    def apply_iptables(self, resolved_ips: dict[str, list[str]]) -> bool:
        """Apply iptables rules. Requires root. Returns True on success."""
        if sys.platform != "linux":
            self.audit.event(
                action=__import__("diana.engagement.audit", fromlist=["AuditAction"]).AuditAction.SCAN_STARTED,
                detail="iptables not available on this platform — skipping L4 enforcement",
            )
            return False

        script = self.generate_iptables_script(resolved_ips)
        try:
            result = subprocess.run(
                ["bash", "-c", script],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                self.audit.event(
                    action=__import__("diana.engagement.audit", fromlist=["AuditAction"]).AuditAction.SCAN_STARTED,
                    detail=f"iptables unavailable (L4 enforcement skipped): {result.stderr.strip()}",
                )
                return False
            return True
        except (subprocess.SubprocessError, OSError) as e:
            self.audit.event(
                action=__import__("diana.engagement.audit", fromlist=["AuditAction"]).AuditAction.SCAN_STARTED,
                detail=f"Failed to apply iptables rules: {e}",
            )
            return False
