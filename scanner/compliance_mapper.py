#!/usr/bin/env python3
"""
LCS-Scanner v5 — Compliance Mapper
Maps scanner findings to multiple compliance frameworks.
Supports: CIS, ISO27001, NIST, GDPR, PCI-DSS
Features:
 - Multi-framework mapping (--compliance multi)
 - Smart keyword-based mapping (title + explain)
 - Multi-match enrichment (adds all relevant frameworks)
 - Graceful fallback with "No direct mapping found"
"""

COMPLIANCE_DB = {
    "cis": {
        "hardcoded": "CIS Control 6.2: Ensure secure credentials management",
        "insecure": "CIS Control 7.4: Use strong cryptographic standards",
        "public": "CIS Control 13.6: Protect data in transit and at rest",
        "password": "CIS Control 5.4: Manage service account credentials securely",
        "api": "CIS Control 4.8: Ensure API security best practices",
    },
    "iso27001": {
        "hardcoded": "ISO 27001 A.9.2.3: Management of privileged access rights",
        "insecure": "ISO 27001 A.10.1.1: Cryptographic controls",
        "public": "ISO 27001 A.13.2.1: Information transfer policies and procedures",
        "password": "ISO 27001 A.9.4.3: Password management system",
        "api": "ISO 27001 A.14.2.1: Secure development policy",
    },
    "nist": {
        "hardcoded": "NIST SP 800-53 IA-5: Authenticator Management",
        "insecure": "NIST SP 800-53 SC-13: Cryptographic Protection",
        "public": "NIST SP 800-53 AC-4: Information Flow Enforcement",
        "password": "NIST SP 800-53 IA-2: Identification and Authentication",
        "api": "NIST SP 800-53 SI-10: Information Input Validation",
    },
    "gdpr": {
        "public": "GDPR Art. 32: Security of processing",
        "password": "GDPR Art. 25: Data protection by design and by default",
        "api": "GDPR Art. 33: Breach notification procedures",
    },
    "pci-dss": {
        "password": "PCI DSS Req. 8.2.3: Strong password requirements",
        "insecure": "PCI DSS Req. 3.6: Cryptographic key management",
        "public": "PCI DSS Req. 4.1: Protect cardholder data in transit",
        "api": "PCI DSS Req. 6.5.7: Prevent exposure through APIs or interfaces",
    }
}


def map_finding(finding, frameworks):
    """
    Map a single finding to one or multiple compliance frameworks.

    Args:
        finding (dict): Finding object containing 'title' or 'explain'
        frameworks (list or str): Framework(s) to map against
    """
    if isinstance(frameworks, str):
        frameworks = [frameworks]

    desc = (finding.get("title", "") + " " + finding.get("explain", "")).lower()
    compliance_hits = {}

    for fw in frameworks:
        rules = COMPLIANCE_DB.get(fw.lower(), {})
        for keyword, control in rules.items():
            if keyword in desc:
                compliance_hits.setdefault(fw.upper(), []).append(control)

    if compliance_hits:
        finding["compliance"] = compliance_hits
    else:
        finding["compliance"] = {"info": ["No direct mapping found"]}

    return finding


def map_findings(findings, frameworks):
    """
    Apply compliance mapping to all findings.

    Args:
        findings (list): List of finding dicts
        frameworks (list or str): Framework(s) to map against
    """
    return [map_finding(f, frameworks) for f in findings]


# Example usage (for testing)
if __name__ == "__main__":
    sample_findings = [
        {"title": "Hardcoded password in API config", "explain": "The API key and password are visible in plaintext."},
        {"title": "Insecure crypto protocol", "explain": "Uses MD5 for hashing instead of SHA-256."},
        {"title": "Public S3 bucket exposed", "explain": "Bucket is publicly accessible without authentication."}
    ]

    result = map_findings(sample_findings, ["cis", "iso27001", "nist", "gdpr", "pci-dss"])
    from pprint import pprint
    pprint(result)
