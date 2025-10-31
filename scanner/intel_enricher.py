#!/usr/bin/env python3
"""
LCS-Scanner v5 — Intel Enricher Module
--------------------------------------
Adds CVE, exploit, and contextual intelligence to findings.

Features (v5):
 - Local simulated intel enrichment
 - Optional NVD stub integration (--intel nvd)
 - CVSS scoring and threat context mapping
"""

import random

# Simulated local threat intelligence dataset
INTEL_DB = [
    {
        "keyword": "password",
        "cve": "CVE-2023-12345",
        "threat": "Credential leakage risk",
        "exploit": "Available in Metasploit",
        "cvss": 8.1,
    },
    {
        "keyword": "ingress",
        "cve": "CVE-2022-56789",
        "threat": "Unrestricted network exposure",
        "exploit": "Exploited in cloud misconfig attacks",
        "cvss": 7.5,
    },
    {
        "keyword": "public access",
        "cve": "CVE-2021-99999",
        "threat": "Sensitive data exposure",
        "exploit": "Used in ransomware campaigns",
        "cvss": 9.0,
    },
]


def enrich_finding(finding, source="local"):
    """
    Add simulated CVE/intel info to a single finding.
    Supports source='local' (default) or 'nvd' (stub mode).
    """
    explain = finding.get("explain", "").lower()

    # NVD stub simulation
    if source == "nvd":
        finding["intel"] = {
            "source": "NVD (stubbed)",
            "cve": f"CVE-{random.randint(2018, 2025)}-{random.randint(1000, 99999)}",
            "threat": random.choice([
                "Privilege escalation vulnerability",
                "Remote code execution risk",
                "Information disclosure issue",
                "Misconfiguration leading to exposure",
            ]),
            "exploit": "No public exploit detected",
            "cvss": round(random.uniform(3.0, 9.8), 1),
        }
        return finding

    # Local enrichment (default)
    for intel in INTEL_DB:
        if intel["keyword"].lower() in explain:
            finding["intel"] = {
                "source": "Local DB",
                "cve": intel["cve"],
                "threat": intel["threat"],
                "exploit": intel["exploit"],
                "cvss": intel["cvss"],
            }
            break
    else:
        # Fallback: simulated intel
        finding["intel"] = {
            "source": "Local DB",
            "cve": None,
            "threat": "No known active exploit.",
            "exploit": "None detected.",
            "cvss": round(random.uniform(2.0, 8.5), 1),
        }

    return finding


def enrich_findings(findings, source="local"):
    """Bulk enrich findings list with threat intel"""
    return [enrich_finding(f, source=source) for f in findings]
