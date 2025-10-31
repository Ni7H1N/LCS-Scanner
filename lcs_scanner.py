#!/usr/bin/env python3
"""
LCS-Scanner v5 — Single-file scanner with advanced report generation
Features:
 - Multi-file scanning (recursively)
 - Built-in rules for AWS/Azure/GCP/Docker/K8s/Helm/Secrets/etc.
 - Intel enrichment (local stub, NVD stub)
 - Compliance mapping (CIS, ISO27001, NIST, PCI-DSS, GDPR)
 - AI contextual explanation (offline heuristics)
 - Exports: JSON, CSV, HTML (futuristic UI)
 - CLI flags: --intel, --intel-source, --compliance, --export-csv, --ai, --futuristic, --threads
"""

import argparse
import os
import sys
import re
import json
import csv
import time
import hashlib
import datetime
import html
import logging
from collections import Counter
from scanner import report_generator
from scanner import rules_engine, compliance_mapper, intel_enricher, report_generator
from concurrent.futures import ThreadPoolExecutor, as_completed

# optional libs
try:
    from tqdm import tqdm
except Exception:
    tqdm = None

try:
    import yara
    YARA_AVAILABLE = True
except Exception:
    yara = None
    YARA_AVAILABLE = False

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except Exception:
    Template = None
    JINJA2_AVAILABLE = False

# color fallback
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except Exception:
    class _C:
        RED = ""
        LIGHTRED_EX = ""
        YELLOW = ""
        CYAN = ""
        WHITE = ""
        GREEN = ""
        MAGENTA = ""
        RESET_ALL = ""
    Fore = _C()
    Style = _C()

# logging
logger = logging.getLogger("lcs-scanner")
logger.setLevel(logging.INFO)
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(h)

# ---------------------------
# Embedded rules (default)
# ---------------------------
_RULES = [
    {"id": "AWS-OPEN-SG", "pattern": r"0\.0\.0\.0/0", "title": "AWS Security Group Allows All Ingress",
     "severity": "High", "explain": "Firewall ingress allows all IPs (0.0.0.0/0).",
     "fix": "Restrict to known CIDRs.", "cwe": "CWE-284", "tags": ["aws", "network"]},

    {"id": "AWS-PUBLIC-S3", "pattern": r"(?i)(public-read|public-read-write)", "title": "Public S3 Bucket ACL",
     "severity": "High", "explain": "S3 bucket publicly readable.", "fix": "Set ACL private and enable block public access.",
     "cwe": "CWE-284", "tags": ["aws", "storage"]},

    {"id": "AWS-HARDCODED-ACCESS", "pattern": r"AKIA[0-9A-Z]{16}", "title": "AWS Access Key Found",
     "severity": "Critical", "explain": "AWS access key ID found in code.", "fix": "Remove from source, rotate credentials.",
     "cwe": "CWE-798", "tags": ["aws", "secrets"]},

    {"id": "AZURE-OPEN-NET", "pattern": r"source_address_prefix\s*=\s*['\"]?(?:\*|0\.0\.0\.0/0)['\"]?",
     "title": "Azure NSG Allows All", "severity": "High", "explain": "Inbound rule exposes entire network.",
     "fix": "Restrict to trusted subnets.", "cwe": "CWE-284", "tags": ["azure", "network"]},

    {"id": "AZURE-STORAGE-HTTP", "pattern": r"enable_https_traffic_only\s*=\s*false",
     "title": "Azure Storage Allows HTTP", "severity": "Medium", "explain": "HTTP enabled for Azure storage endpoints.",
     "fix": "Set enable_https_traffic_only=true.", "cwe": "CWE-319", "tags": ["azure", "encryption"]},

    {"id": "GCP-PUBLIC-BUCKET", "pattern": r"(allUsers|allAuthenticatedUsers)",
     "title": "GCP Bucket Public Access", "severity": "High", "explain": "Public binding grants open access to data.",
     "fix": "Remove public members from IAM policy.", "cwe": "CWE-284", "tags": ["gcp", "storage"]},

    {"id": "GCP-SA-KEY", "pattern": r"private_key_id|\"type\":\s*\"service_account\"",
     "title": "GCP Service Account Key Detected", "severity": "High", "explain": "Embedded service account credentials found.",
     "fix": "Use Workload Identity or Secret Manager.", "cwe": "CWE-798", "tags": ["gcp", "secrets"]},

    {"id": "DOCKER-ROOT", "pattern": r"(?m)^\s*USER\s+root\s*$", "title": "Dockerfile Runs As Root",
     "severity": "High", "explain": "Root user increases container privilege risk.", "fix": "Use non-root USER.",
     "cwe": "CWE-250", "tags": ["docker", "privilege"]},

    {"id": "DOCKER-LATEST", "pattern": r":latest\b", "title": "Docker Uses Latest Tag",
     "severity": "Low", "explain": "Non-versioned tag reduces reproducibility.", "fix": "Pin versions or use digest.",
     "cwe": "CWE-829", "tags": ["docker", "versioning"]},

    {"id": "K8S-SECRET-PLAINTEXT", "pattern": r"(?i)apiVersion: v1[\s\S]*kind: Secret[\s\S]*data:",
     "title": "Kubernetes Secret in Plaintext", "severity": "High", "explain": "K8s Secret manifest contains base64 secrets.",
     "fix": "Use external secret manager.", "cwe": "CWE-312", "tags": ["k8s", "secrets"]},

    {"id": "HELM-NO-LIMITS", "pattern": r"resources:\s*\n\s*requests:", "title": "Helm Chart Missing Limits",
     "severity": "Medium", "explain": "Resource limits missing; risk of cluster instability.",
     "fix": "Add CPU/memory limits.", "cwe": "CWE-770", "tags": ["helm", "k8s"]},

    {"id": "HARDCODED-SECRET-GENERIC", "pattern": r"(?i)(secret|token|password|apikey)\s*[:=]\s*['\"][A-Za-z0-9]{8,}['\"]",
     "title": "Hardcoded Secret Detected", "severity": "High", "explain": "Static secret embedded in code/config.",
     "fix": "Use vault or env variables.", "cwe": "CWE-798", "tags": ["secrets", "code"]},

    {"id": "PLAINTEXT-PASSWORD", "pattern": r"password\s*[:=]\s*['\"][^'\"]{6,}['\"]",
     "title": "Plaintext Password Found", "severity": "High", "explain": "Sensitive password hardcoded.",
     "fix": "Use secret manager.", "cwe": "CWE-256", "tags": ["code", "secrets"]},

    {"id": "CI-NO-SECRETS", "pattern": r"(?i)(github_token|gitlab_token|auth_token)\s*[:=]",
     "title": "CI/CD Secret in Pipeline", "severity": "Critical", "explain": "Secret exposed in CI pipeline script.",
     "fix": "Mask secrets in CI environment.", "cwe": "CWE-798", "tags": ["cicd", "secrets"]},

    {"id": "CI-PRIVILEGED", "pattern": r"privileged:\s*true", "title": "Privileged Container in CI",
     "severity": "High", "explain": "Privileged containers can access host devices.",
     "fix": "Run CI jobs with minimal privileges.", "cwe": "CWE-250", "tags": ["cicd", "docker"]},

    {"id": "PYTHON-EVAL", "pattern": r"eval\(", "title": "Use of Python eval()",
     "severity": "High", "explain": "Dynamic code execution via eval() detected.",
     "fix": "Avoid eval(); use safer parsing.", "cwe": "CWE-95", "tags": ["python", "code"]},

    {"id": "JS-INNERHTML", "pattern": r"\.innerHTML\s*=", "title": "JS innerHTML Assignment",
     "severity": "High", "explain": "Potential XSS vulnerability.",
     "fix": "Use textContent or sanitize input.", "cwe": "CWE-79", "tags": ["javascript", "xss"]},

    {"id": "JWT-TOKEN", "pattern": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", "title": "JWT in Source",
     "severity": "High", "explain": "Possible JWT token found", "fix": "Remove token from source", "cwe": None, "tags": ["token"]},

    {"id": "POTENTIAL-PW", "pattern": r"(?i)password\s*=\s*['\"].{2,}['\"]", "title": "Potential password assignment",
     "severity": "Medium", "explain": "Assignment looks like a password.", "fix": "Avoid storing passwords in code", "cwe": None, "tags": ["code", "secrets"]},
]

# compliance mapping small local map (used for mapping final output)
_COMPLIANCE_DB = {
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

# AI / CWE descriptions
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

# Local intel DB (stub)
INTEL_DB = [
    {"keyword": "password", "cve": "CVE-2023-12345", "threat": "Credential leakage risk", "exploit": "Exploit observed", "cvss": 8.1},
    {"keyword": "ingress", "cve": "CVE-2022-56789", "threat": "Unrestricted network exposure", "exploit": "Exploit observed", "cvss": 7.5},
    {"keyword": "public", "cve": "CVE-2021-99999", "threat": "Sensitive data exposure", "exploit": "Used in campaigns", "cvss": 9.0},
]

# severity -> numeric
_SEV_SCORE = {"Critical": 9.5, "High": 8.0, "Medium": 5.0, "Low": 2.5, "Info": 0.5}

# ---------------------------
# Helper functions
# ---------------------------
def score_from_severity(sev: str) -> float:
    return _SEV_SCORE.get(sev, 1.0)

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    import math
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return - sum(p * math.log2(p) for p in prob)

def get_ai_context(explain_text: str, tags: list = None, cwe: str = None) -> str:
    lower = (explain_text or "").lower()
    context = []
    if cwe and cwe in CWE_DESCRIPTIONS:
        context.append(CWE_DESCRIPTIONS[cwe])
    if tags:
        readable = [RISK_TAGS.get(t, t.title()) for t in tags]
        if readable:
            context.append("Risk domain(s): " + ", ".join(readable) + ".")
    if any(x in lower for x in ["0.0.0.0", "ingress", "open", "public"]):
        context.append("Unrestricted ingress allows anyone on the internet to reach the resource.")
        context.append(MITIGATION_GUIDES["network"])
    if any(word in lower for word in ["secret", "password", "token", "apikey", "credential"]):
        context.append("Hardcoded or plaintext secrets increase credential theft risk.")
        context.append(MITIGATION_GUIDES["secrets"])
    if any(word in lower for word in ["https", "encrypt", "tls"]):
        context.append("Lack of encryption exposes data to interception.")
        context.append(MITIGATION_GUIDES["encryption"])
    if "docker" in lower or "image" in lower:
        context.append("Container hygiene is crucial for supply-chain trust.")
        context.append(MITIGATION_GUIDES["container"])
    if not context:
        context.append("General security best practice: apply least privilege, validate inputs, and review cloud/IaC against compliance benchmarks.")
        context.append(MITIGATION_GUIDES["compliance"])
    return " ".join(context)

def enrich_finding_with_intel(finding: dict, source: str = "local") -> dict:
    explain = (finding.get("explain") or "").lower()
    if source == "nvd":
        import random
        finding["intel"] = {
            "source": "NVD (stub)",
            "cve": f"CVE-{random.randint(2018, 2025)}-{random.randint(1000,99999)}",
            "threat": random.choice(["RCE risk", "Privilege escalation", "Information disclosure", "Exposure via misconfig"]),
            "exploit": "No public exploit detected (stub)",
            "cvss": round(random.uniform(3.0, 9.8), 1),
        }
        return finding
    for intel in INTEL_DB:
        if intel["keyword"] in explain:
            finding["intel"] = {
                "source": "Local DB",
                "cve": intel["cve"],
                "threat": intel["threat"],
                "exploit": intel["exploit"],
                "cvss": intel["cvss"],
            }
            return finding
    import random
    finding["intel"] = {"source": "Local DB", "cve": None, "threat": "No known active exploit.", "exploit": "None detected", "cvss": round(random.uniform(2.0,7.1), 1)}
    return finding

def map_finding_to_compliance(finding: dict, frameworks) -> dict:
    if isinstance(frameworks, str):
        frameworks = [frameworks]
    desc = ((finding.get("title") or "") + " " + (finding.get("explain") or "")).lower()
    hits = {}
    for fw in frameworks:
        rules = _COMPLIANCE_DB.get(fw.lower(), {})
        for keyword, control in rules.items():
            if keyword in desc:
                hits.setdefault(fw.upper(), []).append(control)
    if hits:
        finding["compliance"] = hits
    else:
        finding.setdefault("compliance", {})
        finding["compliance"].setdefault("info", ["No direct mapping found"])
    return finding

def map_findings_to_compliance(findings: list, frameworks) -> list:
    if isinstance(frameworks, str) and frameworks.lower() == "multi":
        frameworks = list(_COMPLIANCE_DB.keys())
    return [map_finding_to_compliance(f, frameworks) for f in findings]

def heuristic_score(finding: dict) -> dict:
    base = {'Critical': 0.95, 'High': 0.8, 'Medium': 0.6, 'Low': 0.3, 'Info': 0.1}
    s = base.get(finding.get('severity', 'Info'), 0.2)
    match = str(finding.get('match') or "")
    if match:
        ent = shannon_entropy(match)
        if ent > 3.5:
            s += 0.08
        if len(match) < 6:
            s -= 0.12
    explain = (finding.get('explain') or "").lower()
    if 'private key' in explain or 'private' in explain:
        s += 0.08
    if 'password' in explain:
        s -= 0.02
    s = max(0.0, min(0.999, s))
    finding['heuristic_score'] = round(s, 3)
    finding['likely_true_positive'] = s >= 0.5
    return finding

# ---------------------------
# Rule compile and run
# ---------------------------
def compile_rule(rule):
    flags = re.IGNORECASE | re.MULTILINE
    try:
        pat = re.compile(rule["pattern"], flags)
    except Exception:
        pat = re.compile(re.escape(rule.get("pattern","")), flags)
    return (rule, pat)

def run_rules_on_content(file_path: str, content: str, rules=None, custom_rules=None, yara_source=None, compliance_frameworks=None, enable_ai=True):
    findings = []
    rules_to_use = list(custom_rules or []) + list(rules or _RULES)
    compiled = []
    for r in rules_to_use:
        try:
            compiled.append(compile_rule(r))
        except Exception:
            logger.exception("Failed to compile rule: %s", r.get("id") if isinstance(r, dict) else str(r))
            continue

    for rule, pat in compiled:
        try:
            for m in pat.finditer(content):
                try:
                    match_text = m.group(0)
                except Exception:
                    match_text = str(m)
                sample = content[max(0, (m.start() if hasattr(m,'start') else 0)-200): (m.end() if hasattr(m,'end') else 0)+200] if hasattr(m, 'start') else None
                confidence = "High" if (len(rule.get("pattern",""))>80 or any(x in (rule.get("pattern") or "").lower() for x in ("password","secret","key"))) else "Medium"
                score = score_from_severity(rule.get("severity","Info"))
                uid_input = f"{rule.get('id')}|{file_path}|{(m.start() if hasattr(m,'start') else hashlib.md5(match_text.encode()).hexdigest())}"
                uid = hashlib.md5(uid_input.encode('utf-8')).hexdigest()
                finding = {
                    "uid": uid,
                    "id": rule.get("id"),
                    "title": rule.get("title"),
                    "file": file_path,
                    "severity": rule.get("severity","Info"),
                    "score": score,
                    "confidence": confidence,
                    "explain": rule.get("explain"),
                    "fix": rule.get("fix"),
                    "cwe": rule.get("cwe"),
                    "tags": rule.get("tags", []),
                    "match": match_text,
                    "match_start": m.start() if hasattr(m, 'start') else None,
                    "match_end": m.end() if hasattr(m, 'end') else None,
                    "rule_pattern": rule.get("pattern"),
                }
                if enable_ai:
                    try:
                        finding["ai_context"] = get_ai_context(rule.get("explain",""), finding["tags"], rule.get("cwe"))
                    except Exception:
                        finding["ai_context"] = None
                        logger.exception("AI explainer failed for rule %s", rule.get("id"))
                if compliance_frameworks:
                    try:
                        finding["compliance"] = _map_compliance_local(rule.get("id"), compliance_frameworks)
                    except Exception:
                        finding["compliance"] = {}
                findings.append(finding)
        except re.error:
            logger.exception("Regex error for rule %s", rule.get("id"))

    # YARA matching
    if yara_source and YARA_AVAILABLE:
        try:
            yara_rules = yara.compile(source=yara_source)
            matches = yara_rules.match(data=content)
            for m in matches:
                uid = hashlib.md5(f"YARA|{file_path}|{m.rule}".encode()).hexdigest()
                findings.append({
                    "uid": uid,
                    "id": "YARA-" + m.rule,
                    "title": f"YARA match: {m.rule}",
                    "file": file_path,
                    "severity": "Medium",
                    "score": 4.0,
                    "confidence": "High",
                    "explain": f"YARA rule matched: {m.rule}",
                    "fix": "",
                    "cwe": None,
                    "tags": ["yara"],
                    "match": str(m),
                })
        except Exception:
            logger.exception("YARA processing failed")

    # dedupe by id+file+match_start
    unique = {}
    for f in findings:
        key = (f.get("id"), f.get("file"), f.get("match_start"))
        if key not in unique:
            unique[key] = f
        else:
            if f.get("score",0) > unique[key].get("score",0):
                unique[key] = f
    out = list(unique.values())
    for f in out:
        f.setdefault("score", score_from_severity(f.get("severity","Info")))
        f["numeric_score"] = float(f["score"])
        f["severity_normalized"] = f.get("severity")
        f.setdefault("short_uid", f["uid"][:10])
    return out

def _map_compliance_local(find_id: str, frameworks):
    if not frameworks:
        return {}
    out = {}
    mapping = {
        "AWS-OPEN-SG": {"cis": ["1.2.3"], "nist": ["AC-4"], "iso27001": ["A.13"], "pci-dss": ["1.1"], "gdpr": []},
        "AWS-PUBLIC-S3": {"cis": ["2.4.1"], "nist": ["AC-3"], "iso27001": ["A.8"], "pci-dss": ["3.5"], "gdpr": ["Art. 32"]},
        "AZURE-OPEN-NET": {"cis": ["1.2.3"], "nist": ["AC-4"], "iso27001": ["A.13"], "pci-dss": [], "gdpr": []},
        "DOCKER-ROOT": {"cis": ["N/A"], "nist": ["SI-2"], "iso27001": ["A.12"], "pci-dss": [], "gdpr": []},
        "HARDCODED-SECRET-GENERIC": {"cis": ["3.1.1"], "nist": ["IA-5"], "iso27001": ["A.9"], "pci-dss": ["3.2"], "gdpr": ["Art.32"]},
        "PLAINTEXT-PASSWORD": {"cis": ["3.1.1"], "nist": ["IA-5"], "iso27001": ["A.9"], "pci-dss": ["3.2"], "gdpr": ["Art.32"]},
    }
    mapping_local = mapping.get(find_id, {})
    for fw in frameworks:
        out[fw] = mapping_local.get(fw, [])
    return out

# ---------------------------
# File utilities & scanning
# ---------------------------
SKIP_EXTS = {'.png', '.jpg', '.jpeg', '.gif', '.exe', '.bin', '.zip', '.class', '.so', '.pdf'}

def collect_files(path):
    if os.path.isfile(path):
        return [path]
    files = []
    for root, _, fnames in os.walk(path):
        for fn in fnames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SKIP_EXTS:
                continue
            files.append(os.path.join(root, fn))
    return files

def safe_read_text(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
            return fh.read()
    except Exception as e:
        logger.debug("Read error for %s: %s", path, e)
        return None

def context_analyze(content):
    patterns = {
        "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "pem": re.compile(r'-----BEGIN (?:RSA |EC |DSA |)PRIVATE KEY-----'),
        "jwt": re.compile(r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'),
        "possible_password": re.compile(r'password\s*[:=]\s*["\']?\w{3,}'),
    }
    hits = []
    for name, rx in patterns.items():
        for m in rx.finditer(content):
            hits.append({"type": name, "match": m.group(0)})
    return hits

def scan_file(path, yara_source=None, custom_rules=None, enable_context=True, compliance_frameworks=None, enable_ai=True):
    content = safe_read_text(path)
    if content is None:
        return [{"file": path, "title": "read-error", "severity": "Info", "explain": f"Could not read file", "match": "", "confidence": "Low"}]
    try:
        findings = run_rules_on_content(path, content, rules=_RULES, custom_rules=custom_rules, yara_source=yara_source, compliance_frameworks=compliance_frameworks, enable_ai=enable_ai)
        if enable_context:
            ctx = context_analyze(content)
            for c in ctx:
                findings.append({
                    "uid": hashlib.md5((path + c['match']).encode()).hexdigest(),
                    "id": f"ctx_{c['type']}",
                    "title": f"Context: {c['type']}",
                    "file": path,
                    "severity": "High" if c['type'] in ('aws_key','pem','jwt') else "Medium",
                    "score": 7.5 if c['type'] in ('aws_key','pem','jwt') else 4.0,
                    "confidence": "High",
                    "explain": f"Contextual secret pattern ({c['type']})",
                    "fix": "",
                    "cwe": None,
                    "tags": [c['type']],
                    "match": c['match'],
                    "match_start": None,
                    "match_end": None,
                })
        return findings
    except RecursionError:
        return [{"file": path, "title": "scan-error", "severity": "Info", "explain": f"Exception during scan: RecursionError", "match": "", "confidence": "Low"}]
    except Exception as e:
        logger.exception("Exception scanning file %s", path)
        return [{"file": path, "title": "scan-error", "severity": "Info", "explain": f"Exception during scan: {e}", "match": "", "confidence": "Low"}]

# ---------------------------
# Exports: JSON/CSV/HTML
# ---------------------------
def save_json(findings, path):
    try:
        with open(path, 'w', encoding='utf-8') as jf:
            json.dump(findings, jf, indent=2)
        logger.info("JSON report: %s", path)
    except Exception:
        logger.exception("Failed to write JSON report")

def save_csv(findings, path):
    keys = ['uid','id','title','file','severity','numeric_score','heuristic_score','confidence','cwe','intel','explain','fix']
    try:
        with open(path, 'w', newline='', encoding='utf-8') as fh:
            w = csv.DictWriter(fh, fieldnames=keys, extrasaction='ignore')
            w.writeheader()
            for f in findings:
                row = {}
                for k in keys:
                    v = f.get(k, '')
                    if isinstance(v, (dict, list)):
                        row[k] = json.dumps(v)
                    else:
                        row[k] = v
                w.writerow(row)
        logger.info("CSV report: %s", path)
    except Exception:
        logger.exception("Failed to write CSV report")

# Futuristic HTML template (condensed and embedded). Uses Chart.js + GSAP via CDN.
HTML_FUTURISTIC = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>🚀 LCS-Scanner — Futuristic CyberOps Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/gsap.min.js"></script>
<style>
/* compacted theme for embedded template (same as earlier design) */
:root{--bg:#04050a;--panel:#071028aa;--accent:#22d3ee;--accent2:#7c3aed;--muted:#94a3b8}
body{background:linear-gradient(180deg,#02040a,#051025);color:#e6eef8;font-family:Inter,Arial;padding:28px;margin:0}
.wrap{max-width:1200px;margin:0 auto}
h1{font-weight:700;font-size:28px;background:linear-gradient(90deg,var(--accent),var(--accent2));-webkit-background-clip:text;color:transparent}
.card{background:rgba(7,16,40,0.6);border-radius:12px;padding:14px;border:1px solid rgba(255,255,255,0.03);margin-top:12px}
.finding{background:linear-gradient(180deg,rgba(7,16,40,0.7),rgba(2,6,16,0.45));padding:12px;border-radius:10px;margin-top:10px;border:1px solid rgba(124,58,237,0.03)}
.meta{color:var(--muted);font-size:13px}
.badge{display:inline-block;padding:4px 8px;border-radius:999px;background:rgba(255,255,255,0.02);font-size:12px;color:var(--muted)}
.sev{display:inline-block;padding:6px 10px;border-radius:999px;font-weight:700;color:#031126}
.sev-High{background:#ef4444;color:white}.sev-Critical{background:#7f1d1d;color:white}.sev-Medium{background:#f97316;color:white}.sev-Low{background:#16a34a;color:#062015}.sev-Info{background:#3b82f6;color:white}
.search,select{padding:8px;border-radius:8px;border:1px solid rgba(255,255,255,0.03);background:transparent;color:inherit}
.footer{color:var(--muted);margin-top:20px;text-align:center}
@media (max-width:900px){.two-col{display:block}}
</style>
</head>
<body>
<div class="wrap">
  <h1>LCS-Scanner — Futuristic CyberOps Report</h1>
  <div class="meta">Generated: {{ generated }}</div>

  <div class="card" style="display:flex;gap:18px;align-items:center;">
    <div style="flex:1">
      <div style="font-weight:700">Summary</div>
      <div class="meta">{{ issue_count }} findings • {{ file_count }} files scanned • Top tags: {{ top_tags }}</div>
    </div>
    <div style="width:340px;">
      <canvas id="sevChart" height="120"></canvas>
    </div>
  </div>

  <div class="card">
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <input id="searchBox" class="search" placeholder="Search findings...">
      <select id="sevFilter" class="search"><option value="">Severity</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select>
      <select id="tagFilter" class="search"><option value="">Tag</option>{% for tag,_ in top_tag_list %}<option value="{{tag}}">{{tag}}</option>{% endfor %}</select>
      <div style="flex:1"></div>
      <button onclick="exportJSON()">JSON</button>
      <button onclick="exportCSV()">CSV</button>
      <button onclick="window.print()">Print</button>
    </div>

    <div id="findings">
      {% for f in findings %}
      <div class="finding" data-sev="{{ f.severity }}" data-tags="{{ f.tags|join(',') }}" data-title="{{ f.title|lower }}">
        <div style="display:flex;justify-content:space-between">
          <div><strong>{{ f.title }}</strong><div class="meta">{{ f.file }} • <span class="badge">{{ f.tags|join(', ') }}</span></div></div>
          <div style="text-align:right">
            <div class="meta">Confidence: {{ f.confidence }}</div>
            <div style="height:6px"></div>
            <div class="sev sev-{{ f.severity }}">{{ f.severity }}</div>
          </div>
        </div>
        <div style="margin-top:8px" class="meta"><b>Explain:</b> {{ f.explain }}</div>
        {% if f.ai_context %}<div style="margin-top:6px" class="meta"><b>AI Context:</b> {{ f.ai_context }}</div>{% endif %}
        {% if f.intel %}<div style="margin-top:6px" class="meta"><b>Intel:</b> {{ f.intel }}</div>{% endif %}
            {% if f.compliance %}
                <div style="margin-top:6px" class="meta">
                   <b>Compliance:</b>
               {% for fw, ctrls in f.compliance.items() %}
                  <div><b>{{ fw }}:</b> {{ ctrls|join(', ') }}</div>
              {% endfor %}
            </div>
{% endif %}

      </div>
      {% endfor %}
    </div>
  </div>

  <div class="footer">LCS-Scanner • Generated {{ generated }}</div>
</div>

<script>
const findings = {{ findings_json|safe }};

function exportJSON(){
  const blob = new Blob([JSON.stringify(findings, null, 2)], {type:'application/json'});
  const a = document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='lcs_report.json'; a.click();
}
function exportCSV(){
  const rows = [["id","title","file","severity","score","confidence","tags","fix"]];
  findings.forEach(f => rows.push([f.uid||f.id,f.title,f.file,f.severity,f.score,f.confidence,(f.tags||[]).join(';'),f.fix||'']));
  const csv = rows.map(r => r.map(c => `"${String(c||'').replace(/"/g,'""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], {type:'text/csv'}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='lcs_report.csv'; a.click();
}

function buildChart(){
  const ctx = document.getElementById('sevChart').getContext('2d');
  const sevCounts = {Critical:0,High:0,Medium:0,Low:0,Info:0};
  findings.forEach(f => { sevCounts[f.severity] = (sevCounts[f.severity]||0) + 1; });
  new Chart(ctx, {type:'doughnut', data:{labels:Object.keys(sevCounts), datasets:[{data:Object.values(sevCounts), backgroundColor:['#7f1d1d','#ef4444','#f97316','#16a34a','#3b82f6']}]}, options:{plugins:{legend:{position:'bottom'}}}});
}
buildChart();

// ✅ Fix GSAP animation timing to load after chart
setTimeout(() => {
  gsap.from(".finding", {duration:0.6,opacity:0,stagger:0.05,delay:0.5});
}, 600);

function applyFilters(){
  const q = (document.getElementById('searchBox').value||'').toLowerCase();
  const sev = document.getElementById('sevFilter').value;
  const tag = (document.getElementById('tagFilter').value||'').toLowerCase();
  document.querySelectorAll('.finding').forEach(el=>{
    const title = el.dataset.title||'';
    const tags = el.dataset.tags||'';
    const matches = (!q || title.includes(q)) && (!sev || el.dataset.sev===sev) && (!tag || tags.toLowerCase().includes(tag));
    el.style.display = matches ? 'block' : 'none';
  });
}
document.getElementById('searchBox').addEventListener('input', applyFilters);
document.getElementById('sevFilter').addEventListener('change', applyFilters);
document.getElementById('tagFilter').addEventListener('change', applyFilters);
</script>
</body>
</html>
"""

# Minimal fallback HTML if jinja2 missing (safe)
HTML_MINIMAL = """
<!doctype html>
<html><head><meta charset="utf-8"><title>LCS-Scanner Report</title></head><body>
<h1>LCS-Scanner Report</h1>
<pre id="data"></pre>
<script>
const data = {{ findings_json|safe }};
document.getElementById('data').innerText = JSON.stringify(data, null, 2);
</script>
</body></html>
"""

def generate_full_html(findings, out_path, futuristic=False):
    generated = datetime.datetime.now(datetime.timezone.utc).isoformat()
    file_counts = Counter([f.get('file','unknown') for f in findings]).most_common(50)
    file_count = len(set([f.get('file') for f in findings]))
    issue_count = len(findings)
    high_count = sum(1 for f in findings if f.get('severity') in ('High','Critical'))
    medium_count = sum(1 for f in findings if f.get('severity') == 'Medium')
    low_count = sum(1 for f in findings if f.get('severity') in ('Low','Info'))

    tag_counter = Counter()
    for f in findings:
        for t in f.get('tags', []) if isinstance(f.get('tags', []), list) else []:
            tag_counter[t] += 1
    top_tags = ", ".join([t for t,_ in tag_counter.most_common(8)])
    top_tag_list = tag_counter.most_common(20)

    # sanitize string fields for safe HTML rendering inside template blocks
    safe_findings = []
    for f in findings:
        sf = {}
        for k,v in f.items():
            if isinstance(v, (str,int,float)) or v is None:
                sf[k] = html.escape(str(v)) if v is not None else ''
            else:
                sf[k] = v
        safe_findings.append(sf)

    # choose template
    tpl_text = HTML_FUTURISTIC if futuristic else (HTML_FUTURISTIC if JINJA2_AVAILABLE else HTML_MINIMAL)

    # render using jinja2 if available, else write minimal by substituting JSON raw
    if JINJA2_AVAILABLE:
        tpl = Template(tpl_text)
        out = tpl.render(
            generated=generated,
            findings=safe_findings,
            findings_json=json.dumps(findings),
            file_counts=file_counts,
            file_count=file_count,
            issue_count=issue_count,
            top_tags=top_tags,
            top_tag_list=top_tag_list,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count
        )
    else:
        # fallback: embed raw JSON in minimal template
        out = HTML_MINIMAL.replace("{{ findings_json|safe }}", json.dumps(findings))

    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as fh:
        fh.write(out)
    logger.info("HTML report: %s", out_path)

# ---------------------------
# CLI main and runner
# ---------------------------
class PerfMeter:
    def __init__(self):
        self.start = time.time()
        self.files = 0
        self.findings = 0
    def tick_file(self):
        self.files += 1
    def add_findings(self, n):
        self.findings += n
    def report(self):
        elapsed = time.time() - self.start
        return {'elapsed_s': round(elapsed,2), 'files': self.files, 'findings': self.findings, 'fps': round(self.files/elapsed,2) if elapsed>0 else 0}

def load_custom_rules(path):
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        logger.exception("Failed to load custom rules")
        return None

def check_cve_db_update(db_path=None, force=False):
    if not db_path:
        db_path = os.path.expanduser('~/.lcs_cve_db.json')
    if force:
        logger.info("CVE DB check (forced) -> %s (placeholder)", db_path)
        return True
    if not os.path.exists(db_path):
        logger.info("Local CVE DB not found at %s (placeholder).", db_path)
        return False
    age = time.time() - os.path.getmtime(db_path)
    if age > 60*60*24*7:
        logger.info("Local CVE DB older than 7 days — consider updating.")
        return False
    return True

def print_summary(findings, perf=None):
    c = Counter()
    files = Counter()
    for f in findings:
        c[f.get('severity','Info')] += 1
        files[f.get('file','unknown')] += 1
    print("\n=== Scan Summary ===")
    print(f"Files scanned: {len(set([f['file'] for f in findings]))}")
    print(f"Total findings: {len(findings)}")
    colors = {'Critical': Fore.RED, 'High': Fore.LIGHTRED_EX, 'Medium': Fore.YELLOW, 'Low': Fore.CYAN, 'Info': Fore.WHITE}
    for sev in ["Critical","High","Medium","Low","Info"]:
        if c.get(sev):
            print(f"  {colors.get(sev,'')}{sev}: {c[sev]}{Style.RESET_ALL}")
    print("\nTop affected files:")
    for fname, count in files.most_common(10):
        print(f"  {fname}: {count}")
    if perf:
        print("\nPerformance:")
        for k,v in perf.items():
            print(f"  {k}: {v}")
    print("====================\n")

def main():
    p = argparse.ArgumentParser(description='LCS-Scanner v5 — Advanced Local Cloud Security Scanner')
    p.add_argument('--path','-p',default='./samples',help='Path or file to scan')
    p.add_argument('--out','-o',default='./reports',help='Output folder for reports')
    p.add_argument('--summary',action='store_true',help='Only print summary + exit')
    p.add_argument('--fail-on-high',action='store_true',help='Exit code 1 if High/Critical findings exist')
    p.add_argument('--no-html',action='store_true',help='Do not generate HTML report')
    p.add_argument('--json-only',action='store_true',help='Only produce JSON output (no HTML, no printing details)')
    p.add_argument('--intel',action='store_true',help='Enable CVE & Exploit intelligence enrichment')
    p.add_argument('--intel-source',choices=['local','nvd'],default='local',help='Intel source for enrichment')
    p.add_argument('--compliance',choices=['cis','iso27001','nist','pci-dss','gdpr','multi','none'],default='none',help='Map findings to compliance framework')
    p.add_argument('--rules',help='Path to custom rules JSON')
    p.add_argument('--yara',help='Path to YARA source file (string content)')
    p.add_argument('--threads',type=int,default=6,help='Parallel worker threads')
    p.add_argument('--v5',action='store_true',help='Enable v5 features (placeholder)')
    p.add_argument('--export-csv',action='store_true',help='Also export CSV')
    p.add_argument('--cve-db',help='Path to local CVE DB to check/augment (optional)')
    p.add_argument('--force-cve-update',action='store_true',help='Force CVE DB update placeholder')
    p.add_argument('--ai',action='store_true',help='Enable AI-assisted contextual analysis (experimental)')
    p.add_argument('--futuristic',action='store_true',help='Use futuristic animated HTML report (Chart.js + GSAP)')
    args = p.parse_args()

    os.makedirs(args.out, exist_ok=True)
    print(f"📁 Scanning: {args.path}")

    custom_rules = None
    if args.rules:
        custom_rules = load_custom_rules(args.rules)

    yara_source = None
    if args.yara:
        if os.path.exists(args.yara):
            try:
                with open(args.yara, 'r', encoding='utf-8') as fh:
                    yara_source = fh.read()
            except Exception:
                yara_source = args.yara
        else:
            yara_source = args.yara

    if args.v5:
        check_cve_db_update(db_path=args.cve_db, force=args.force_cve_update)

    files = collect_files(args.path)
    perf = PerfMeter()
    all_findings = []
    use_tqdm = tqdm is not None
    iterator = files
    if use_tqdm:
        iterator = tqdm(files, desc='Scanning files')

    compliance_frameworks = None
    if args.compliance and args.compliance != 'none':
        compliance_frameworks = args.compliance if args.compliance != 'multi' else list(_COMPLIANCE_DB.keys())

    # scan in threads
    with ThreadPoolExecutor(max_workers=max(2, args.threads)) as ex:
        future_to_file = {
            ex.submit(
                scan_file,
                f,
                yara_source,
                custom_rules,
                True,
                (None if compliance_frameworks is None else compliance_frameworks),
                args.ai
            ): f for f in files
        }
        for fut in as_completed(future_to_file):
            fpath = future_to_file[fut]
            perf.tick_file()
            try:
                findings = fut.result()
            except Exception as e:
                findings = [{"file": fpath, "title": "scan-error", "severity": "Info", "explain": f"Exception during scan: {e}", "match": "", "confidence": "Low"}]
            for f in findings:
                heuristic_score(f)
            all_findings.extend(findings)
            perf.add_findings(len(findings))
            if use_tqdm:
                try:
                    iterator.update(1)
                except Exception:
                    pass

    # intel enrichment
    if args.intel:
        try:
            all_findings = [enrich_finding_with_intel(f, source=args.intel_source) for f in all_findings]
        except Exception:
            logger.exception("Intel enrichment failed - fallback to minimal")
            all_findings = [enrich_finding_with_intel(f) for f in all_findings]

    # ✅ Dynamic compliance mapping (multi-framework aware)
    if args.compliance and args.compliance != 'none':
        try:
            from scanner import compliance_mapper
            all_findings = compliance_mapper.map_findings(all_findings, args.compliance)
            logger.info("Compliance mapping completed dynamically for framework(s): %s", args.compliance)
        except Exception as e:
            logger.warning("Dynamic compliance mapping failed: %s — falling back to internal map", e)
            try:
                all_findings = map_findings_to_compliance(all_findings, args.compliance)
            except Exception:
                logger.exception("Internal compliance mapping also failed.")

    # compliance mapping
    if args.compliance and args.compliance != 'none':
        try:
            all_findings = map_findings_to_compliance(all_findings, args.compliance)
        except Exception:
            logger.exception("Compliance mapping failed - fallback")
            all_findings = map_findings_to_compliance(all_findings, args.compliance)

    # Save JSON
    json_path = os.path.join(args.out, 'report.json')
    save_json(all_findings, json_path)

    # Save CSV
    if args.export_csv:
        csv_path = os.path.join(args.out, 'report.csv')
        save_csv(all_findings, csv_path)

    # Generate HTML
    html_path = os.path.join(args.out, 'report.html')
    if not args.no_html and not args.json_only:
        try:
            generate_full_html(all_findings, html_path, futuristic=args.futuristic)
        except Exception:
            logger.exception("HTML generation failed - writing minimal file")
            try:
                with open(html_path, 'w', encoding='utf-8') as fh:
                    fh.write("<html><body><pre>" + html.escape(json.dumps(all_findings, indent=2)) + "</pre></body></html>")
                logger.info("HTML (minimal): %s", html_path)
            except Exception:
                logger.exception("Failed to write minimal HTML report")
    # Auto-open HTML report (optional)
    try:
        import webbrowser
        if not args.no_html and not args.json_only:
            abs_path = os.path.abspath(html_path)
            webbrowser.open(f"file://{abs_path}")
            logger.info(f"Opened report in browser: {abs_path}")
    except Exception as e:
        logger.warning(f"Failed to auto-open report: {e}")
    # console output
    if not args.json_only:
        for f in all_findings:
            title = f.get('title') or f.get('id') or 'Unknown Issue'
            print(f"[!] {title} — {f.get('file')}")
            print(f"    → Risk: {f.get('severity','Info')}")
            if f.get('cwe'):
                print(f"    → CWE: {f.get('cwe')}")
            if f.get('score') is not None:
                try:
                    print(f"    → Score: {f.get('score'):.1f}")
                except Exception:
                    print(f"    → Score: {f.get('score')}")
            if f.get('heuristic_score') is not None:
                print(f"    → Heuristic: {f.get('heuristic_score')} (likely TP: {f.get('likely_true_positive')})")
            if f.get('confidence'):
                print(f"    → Confidence: {f.get('confidence')}")
            if f.get('intel'):
                print(f"    → Intel: {f.get('intel')}")
            if f.get('compliance'):
                print(f"    → Compliance: {f.get('compliance')}")
            if f.get('ai_context'):
                print(f"    → AI Context: {f.get('ai_context')}")
            print(f"    → Explain: {f.get('explain')}")
            if f.get('fix'):
                print(f"    → Fix: {f.get('fix')}")
            print("")

    perf_report = perf.report()
    print_summary(all_findings, perf_report)

    if args.fail_on_high and any(f['severity'] in ('High','Critical') and f.get('likely_true_positive', True) for f in all_findings):
        print('Failing on high/critical findings (exit code 1).')
        sys.exit(1)

    sys.exit(0)

if __name__ == '__main__':
    main()
