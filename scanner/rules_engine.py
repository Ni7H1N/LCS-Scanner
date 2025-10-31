# scanner/rules_engine.py — Advanced Multi-Cloud Rules Engine v5.2
# -----------------------------------------------------------------
# Features:
#  - Multi-cloud + container + IaC + code + secret detections
#  - Threat scoring + confidence model
#  - Multi-framework compliance hooks (supports multi-select)
#  - AI explain context hook (uses scanner.ai_explainer)
#  - Optional YARA integration (if yara-python installed)
#  - Custom rules injection + external rule pack loading
#  - De-duplication + deterministic UIDs + priority tagging
# -----------------------------------------------------------------

import re
import hashlib
import logging
import json
from typing import List, Dict, Optional, Iterable, Tuple

from scanner import ai_explainer

# Optional YARA support
try:
    import yara
    YARA_AVAILABLE = True
except Exception:
    yara = None
    YARA_AVAILABLE = False

logger = logging.getLogger(__name__)

# --- Base score mapping (severity -> base numeric score out of 10) ---
_SEV_SCORE = {"Critical": 9.5, "High": 8.0, "Medium": 5.0, "Low": 2.5, "Info": 0.5}


def _score_from_severity(sev: str) -> float:
    return _SEV_SCORE.get(sev, 1.0)


def _confidence_from_pattern(pattern: str, content_sample: Optional[str] = None) -> str:
    """Heuristic confidence scoring: Low / Medium / High"""
    pat = (pattern or "").lower()
    if len(pattern or "") > 80:
        return "High"
    if "0.0.0.0" in pat or "public" in pat:
        return "High"
    if "password" in pat or "secret" in pat or "key" in pat:
        return "High"
    if content_sample:
        cs = content_sample.lower()
        if "-----begin " in cs or "private key" in cs:
            return "High"
    return "Medium"


# --- Compliance reference map ---
_COMPLIANCE_MAP = {
    "AWS-OPEN-SG": {"cis": ["1.2.3"], "nist": ["AC-4"], "iso27001": ["A.13"], "pci-dss": ["1.1"], "gdpr": []},
    "AWS-PUBLIC-S3": {"cis": ["2.4.1"], "nist": ["AC-3"], "iso27001": ["A.8"], "pci-dss": ["3.5"], "gdpr": ["Art. 32"]},
    "AZURE-OPEN-NET": {"cis": ["1.2.3"], "nist": ["AC-4"], "iso27001": ["A.13"], "pci-dss": [], "gdpr": []},
    "DOCKER-ROOT": {"cis": ["N/A"], "nist": ["SI-2"], "iso27001": ["A.12"], "pci-dss": [], "gdpr": []},
    "HARDCODED-SECRET-GENERIC": {"cis": ["3.1.1"], "nist": ["IA-5"], "iso27001": ["A.9"], "pci-dss": ["3.2"], "gdpr": ["Art.32"]},
}


# --- Default rule set (categorized) ---
RULES = [
    # === AWS ===
    {"id": "AWS-OPEN-SG", "pattern": r"0\.0\.0\.0/0", "title": "AWS Security Group Allows All Ingress",
     "severity": "High", "explain": "Firewall ingress allows all IPs (0.0.0.0/0).",
     "fix": "Restrict to known CIDRs.", "cwe": "CWE-284",
     "tags": ["aws", "network"], "category": "Cloud Misconfiguration"},

    {"id": "AWS-PUBLIC-S3", "pattern": r"(?i)(public-read|public-read-write)", "title": "Public S3 Bucket ACL",
     "severity": "High", "explain": "S3 bucket publicly readable.",
     "fix": "Set ACL private and enable block public access.", "cwe": "CWE-284",
     "tags": ["aws", "storage"], "category": "Cloud Misconfiguration"},

    {"id": "AWS-HARDCODED-ACCESS", "pattern": r"AKIA[0-9A-Z]{16}", "title": "AWS Access Key Found",
     "severity": "Critical", "explain": "AWS access key ID found in code.",
     "fix": "Remove from source, rotate credentials.", "cwe": "CWE-798",
     "tags": ["aws", "secrets"], "category": "Secrets Exposure"},

    # === Azure ===
    {"id": "AZURE-OPEN-NET", "pattern": r"source_address_prefix\s*=\s*['\"]?(?:\*|0\.0\.0\.0/0)['\"]?",
     "title": "Azure NSG Allows All", "severity": "High",
     "explain": "Inbound rule exposes entire network.",
     "fix": "Restrict to trusted subnets.", "cwe": "CWE-284",
     "tags": ["azure", "network"], "category": "Cloud Misconfiguration"},

    {"id": "AZURE-STORAGE-HTTP", "pattern": r"enable_https_traffic_only\s*=\s*false",
     "title": "Azure Storage Allows HTTP", "severity": "Medium",
     "explain": "HTTP enabled for Azure storage endpoints.",
     "fix": "Set enable_https_traffic_only=true.", "cwe": "CWE-319",
     "tags": ["azure", "encryption"], "category": "Encryption Weakness"},

    # === GCP ===
    {"id": "GCP-PUBLIC-BUCKET", "pattern": r"(allUsers|allAuthenticatedUsers)",
     "title": "GCP Bucket Public Access", "severity": "High",
     "explain": "Public binding grants open access to data.",
     "fix": "Remove public members from IAM policy.", "cwe": "CWE-284",
     "tags": ["gcp", "storage"], "category": "Cloud Misconfiguration"},

    {"id": "GCP-SA-KEY", "pattern": r"private_key_id|\"type\":\s*\"service_account\"",
     "title": "GCP Service Account Key Detected", "severity": "High",
     "explain": "Embedded service account credentials found.",
     "fix": "Use Workload Identity or Secret Manager.", "cwe": "CWE-798",
     "tags": ["gcp", "secrets"], "category": "Secrets Exposure"},

    # === Docker ===
    {"id": "DOCKER-ROOT", "pattern": r"(?m)^\s*USER\s+root\s*$", "title": "Dockerfile Runs As Root",
     "severity": "High", "explain": "Root user increases container privilege risk.",
     "fix": "Use non-root USER.", "cwe": "CWE-250", "tags": ["docker", "privilege"],
     "category": "Container Security"},

    {"id": "DOCKER-LATEST", "pattern": r":latest", "title": "Docker Uses Latest Tag",
     "severity": "Low", "explain": "Non-versioned tag reduces reproducibility.",
     "fix": "Pin versions or use digest.", "cwe": "CWE-829", "tags": ["docker", "versioning"],
     "category": "Version Control"},

    # === K8s & Helm ===
    {"id": "K8S-SECRET-PLAINTEXT", "pattern": r"(?i)apiVersion: v1[\s\S]*kind: Secret[\s\S]*data:",
     "title": "Kubernetes Secret in Plaintext", "severity": "High",
     "explain": "K8s Secret manifest contains base64 secrets.",
     "fix": "Use external secret manager.", "cwe": "CWE-312", "tags": ["k8s", "secrets"],
     "category": "Secrets Exposure"},

    {"id": "HELM-NO-LIMITS", "pattern": r"resources:\s*\n\s*requests:",
     "title": "Helm Chart Missing Limits", "severity": "Medium",
     "explain": "Resource limits missing; risk of cluster instability.",
     "fix": "Add CPU/memory limits.", "cwe": "CWE-770", "tags": ["helm", "k8s"],
     "category": "Resource Management"},

    # === Secrets & Code ===
    {"id": "HARDCODED-SECRET-GENERIC", "pattern": r"(?i)(secret|token|password|apikey)\s*[:=]\s*['\"][A-Za-z0-9]{8,}['\"]",
     "title": "Hardcoded Secret Detected", "severity": "High",
     "explain": "Static secret embedded in code/config.",
     "fix": "Use vault or env variables.", "cwe": "CWE-798", "tags": ["secrets", "code"],
     "category": "Secrets Exposure"},

    {"id": "PLAINTEXT-PASSWORD", "pattern": r"password\s*[:=]\s*['\"][^'\"]{6,}['\"]",
     "title": "Plaintext Password Found", "severity": "High",
     "explain": "Sensitive password hardcoded.",
     "fix": "Use secret manager.", "cwe": "CWE-256", "tags": ["code", "secrets"],
     "category": "Secrets Exposure"},

    # === CI/CD ===
    {"id": "CI-NO-SECRETS", "pattern": r"(?i)(github_token|gitlab_token|auth_token)\s*[:=]",
     "title": "CI/CD Secret in Pipeline", "severity": "Critical",
     "explain": "Secret exposed in CI pipeline script.",
     "fix": "Mask secrets in CI environment.", "cwe": "CWE-798", "tags": ["cicd", "secrets"],
     "category": "Pipeline Security"},

    {"id": "CI-PRIVILEGED", "pattern": r"privileged:\s*true",
     "title": "Privileged Container in CI", "severity": "High",
     "explain": "Privileged containers can access host devices.",
     "fix": "Run CI jobs with minimal privileges.", "cwe": "CWE-250", "tags": ["cicd", "docker"],
     "category": "Pipeline Security"},

    # === Language-specific ===
    {"id": "PYTHON-EVAL", "pattern": r"eval\(", "title": "Use of Python eval()",
     "severity": "High", "explain": "Dynamic code execution via eval() detected.",
     "fix": "Avoid eval(); use safer parsing.", "cwe": "CWE-95", "tags": ["python", "code"],
     "category": "Code Execution Risk"},

    {"id": "JS-INNERHTML", "pattern": r"\.innerHTML\s*=", "title": "JS innerHTML Assignment",
     "severity": "High", "explain": "Potential XSS vulnerability.",
     "fix": "Use textContent or sanitize input.", "cwe": "CWE-79", "tags": ["javascript", "xss"],
     "category": "Web Security"},
]


# --- Custom Rule Loader ---
def load_custom_ruleset(file_path: str) -> list:
    """Load additional rule packs (JSON list)."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                logger.info(f"Loaded {len(data)} custom rules from {file_path}")
                return data
    except Exception as e:
        logger.warning(f"Failed to load custom rule pack: {e}")
    return []


def _compile_rule(rule: Dict) -> Tuple[Dict, re.Pattern]:
    flags = re.IGNORECASE | re.MULTILINE
    try:
        pattern = re.compile(rule["pattern"], flags)
    except re.error:
        pattern = re.compile(re.escape(rule["pattern"]), flags)
    return rule, pattern


def _map_compliance(find_id: str, frameworks: Iterable[str]) -> Dict[str, list]:
    if not frameworks:
        return {}
    out = {}
    mapping = _COMPLIANCE_MAP.get(find_id, {})
    for fw in frameworks:
        out[fw] = mapping.get(fw, [])
    return out


def run_rules(file_path: str,
              content: str,
              rules: Optional[Iterable[Dict]] = None,
              custom_rules: Optional[Iterable[Dict]] = None,
              yara_source: Optional[str] = None,
              compliance_frameworks: Optional[Iterable[str]] = None,
              enable_ai_context: bool = True) -> List[Dict]:
    """Run the rulebase against content and return findings."""
    if not content or not isinstance(content, str):
        return []

    findings = []
    rules_to_use = list(rules or RULES)
    if custom_rules:
        rules_to_use = list(custom_rules) + rules_to_use

    compiled = []
    for r in rules_to_use:
        try:
            compiled.append(_compile_rule(r))
        except Exception:
            logger.exception("Failed to compile rule: %s", r.get('id'))
            continue

    for rule, pat in compiled:
        try:
            for m in pat.finditer(content):
                match_text = m.group(0)
                sample = content[max(0, m.start() - 200):m.end() + 200]

                confidence = _confidence_from_pattern(rule.get('pattern', ''), sample)
                score = _score_from_severity(rule.get('severity', 'Info'))

                uid_input = f"{rule.get('id')}|{file_path}|{m.start()}"
                uid = hashlib.md5(uid_input.encode('utf-8')).hexdigest()

                finding = {
                    "uid": uid,
                    "id": rule.get("id"),
                    "title": rule.get("title"),
                    "file": file_path,
                    "severity": rule.get("severity", "Info"),
                    "score": score,
                    "confidence": confidence,
                    "explain": rule.get("explain"),
                    "fix": rule.get("fix"),
                    "cwe": rule.get("cwe"),
                    "tags": rule.get("tags", []),
                    "match": match_text,
                    "match_start": m.start(),
                    "match_end": m.end(),
                    "rule_pattern": rule.get("pattern"),
                    "category": rule.get("category", "General"),
                    "cvss": None,
                    "rule_source": rule.get("source", "builtin"),
                    "rule_version": rule.get("version", "v5.2"),
                }

                try:
                    if enable_ai_context:
                        finding["ai_context"] = ai_explainer.get_ai_context(rule.get("explain"))
                except Exception:
                    finding["ai_context"] = None

                if compliance_frameworks:
                    finding["compliance"] = _map_compliance(rule.get("id"), compliance_frameworks)

                findings.append(finding)
        except re.error:
            logger.exception("Regex error for rule %s", rule.get("id"))

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
                })
        except Exception:
            logger.exception("YARA matching failed or yara not available")

    # Deduplicate
    unique = {}
    for f in findings:
        key = (f.get("id"), f.get("file"), f.get("match_start"))
        if key not in unique:
            unique[key] = f
        else:
            if f.get("score", 0) > unique[key].get("score", 0):
                unique[key] = f

    out = list(unique.values())

    # Add enhancements
    for f in out:
        f.setdefault("score", _score_from_severity(f.get("severity", "Info")))
        f["numeric_score"] = float(f["score"])
        f["severity_normalized"] = f.get("severity")
        f["short_uid"] = f["uid"][:10]
        f["suggested_priority"] = "Immediate" if f["severity"] in ("Critical", "High") else "Review"

    logger.info(f"[RulesEngine] {file_path} → {len(out)} finding(s)")
    return out
