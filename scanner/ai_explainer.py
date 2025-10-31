"""
AI Explainer v5 — Rich Offline Context Intelligence
---------------------------------------------------
Features:
 - Deeper CWE → Explainer → Mitigation reasoning
 - Offline ML-lite heuristic classification (keywords, CWE, tags)
 - Risk domain translation for better compliance insights
 - Context-tier labeling for dashboards and reports
"""

CWE_DESCRIPTIONS = {
    "CWE-284": "Improper Access Control — access not properly restricted.",
    "CWE-311": "Missing encryption of sensitive data.",
    "CWE-312": "Cleartext storage of sensitive information.",
    "CWE-319": "Cleartext transmission of sensitive information.",
    "CWE-250": "Execution with unnecessary privileges.",
    "CWE-770": "Resource allocation without proper limits.",
    "CWE-798": "Hard-coded credentials or secrets in code/config.",
    "CWE-256": "Plaintext storage of sensitive credentials.",
    "CWE-829": "Unpinned dependencies / version control issue.",
    "CWE-95": "Improper neutralization of data before evaluation ('eval').",
    "CWE-79": "Cross-Site Scripting (XSS) via unsafe DOM assignment.",
}

RISK_TAGS = {
    "network": "Attack Surface / Network Exposure",
    "secrets": "Credential Management Risk",
    "container": "Supply Chain / Image Integrity",
    "aws": "Cloud Misconfiguration (AWS)",
    "azure": "Cloud Misconfiguration (Azure)",
    "gcp": "Cloud Misconfiguration (GCP)",
    "k8s": "Cluster Security / Pod Risk",
    "helm": "IaC Misconfiguration (Helm)",
    "code": "Source Code Risk",
    "cicd": "Pipeline Security / DevOps Exposure",
    "python": "Dynamic Code Execution Risk",
    "javascript": "Client-Side Scripting Risk",
}

MITIGATION_GUIDES = {
    "access": "Apply least privilege and explicit deny policies.",
    "secrets": "Move secrets to a managed vault service and rotate keys regularly.",
    "encryption": "Use HTTPS/TLS for all communications and AES/KMS for data at rest.",
    "network": "Restrict CIDRs, disable public ingress, use zero-trust firewalls.",
    "container": "Avoid running as root, pin image versions, and enable image signing.",
    "compliance": "Review against CIS, NIST, ISO27001, and PCI-DSS benchmarks.",
}

def get_ai_context(explain_text: str, tags: list[str] | None = None, cwe: str | None = None) -> str:
    """
    Enrich rule explanation with contextual reasoning.
    Supports semantic hints from CWE, tags, and plain text.
    """
    lower = explain_text.lower()
    context = []

    # --- CWE match reasoning ---
    if cwe and cwe in CWE_DESCRIPTIONS:
        context.append(CWE_DESCRIPTIONS[cwe])

    # --- Tag-based contextual reasoning ---
    if tags:
        readable_tags = [RISK_TAGS.get(t, t.title()) for t in tags]
        if readable_tags:
            context.append(f"Risk domain(s): {', '.join(readable_tags)}.")

    # --- Keyword heuristics ---
    if "0.0.0.0" in lower or "ingress" in lower or "open" in lower:
        context.append("Unrestricted ingress allows anyone on the internet to reach the resource.")
        context.append(MITIGATION_GUIDES["network"])

    if any(word in lower for word in ["secret", "password", "token", "apikey", "credential"]):
        context.append("Hardcoded or plaintext secrets increase credential theft risk.")
        context.append(MITIGATION_GUIDES["secrets"])

    if "encrypt" in lower or "https" in lower:
        context.append("Lack of encryption exposes sensitive traffic or data to interception.")
        context.append(MITIGATION_GUIDES["encryption"])

    if "docker" in lower or "image" in lower:
        context.append("Container hygiene is crucial for supply-chain trust.")
        context.append(MITIGATION_GUIDES["container"])

    if "firewall" in lower or "security group" in lower:
        context.append("Review firewall exposure; open rules can violate zero-trust policy.")
        context.append(MITIGATION_GUIDES["network"])

    # --- Default fallback ---
    if not context:
        context.append(
            "General security best practice: Apply least privilege, validate inputs, "
            "and review cloud/IaC configuration against compliance benchmarks."
        )
        context.append(MITIGATION_GUIDES["compliance"])

    return " ".join(context)


def tag_context(tags):
    """Translate technical tags to readable risk domains for reports."""
    if not tags:
        return []
    return [RISK_TAGS.get(t, t.title()) for t in tags]
