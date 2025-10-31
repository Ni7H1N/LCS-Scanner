# ⚡ LCS-Scanner — Cloud & Code Security Analyzer

**Local Cloud Security Compliance Scanner (LCS-Scanner)** is a **zero-cost, offline, AI-explainable DevSecOps toolkit** for **Terraform**, **Dockerfiles**, and **Kubernetes/YAML**.  

It scans Infrastructure-as-Code (IaC) and container configurations for **misconfigurations**, **secrets**, and **policy violations**.  
It also provides **AI-driven explanations**, **multi-framework compliance mapping (CIS, NIST, ISO27001, GDPR)**, and a **futuristic glassy HTML dashboard** — all running **locally** with **zero API cost** or cloud dependency.

Built for **security engineers**, **cloud architects**, and **researchers** who need a **fast, auditable, and visually rich** analyzer that works even in **air-gapped environments**.

---

> 🧠 *Multi-cloud, AI-enhanced, and compliance-aware vulnerability scanner for modern DevSecOps pipelines.*

---

## 🚀 Overview

**LCS-Scanner** is an advanced **multi-framework cloud security analyzer** designed for DevSecOps and SOC teams.  
It intelligently detects misconfigurations, secrets, and insecure code patterns — enriched with **AI context**, **compliance frameworks**, and **beautiful glass-morphic HTML reports**.

---

## 🧩 Key Features

| Category | Description |
|-----------|-------------|
| ☁️ **Cloud Scanning** | Detects open AWS Security Groups, public S3 buckets, and misconfigured Azure or GCP resources. |
| 🐳 **Container Security** | Identifies risky Dockerfile practices (`USER root`, `:latest`, hardcoded secrets). |
| ⚙️ **IaC & Code Scanning** | Parses Terraform, Helm, and Kubernetes YAMLs for insecure defaults. |
| 🧠 **AI Context** | Adds intelligent natural-language context for each finding with remediation guidance. |
| 🛡️ **Compliance Mapping** | Auto-maps findings to **CIS**, **ISO27001**, **NIST**, **PCI-DSS**, and **GDPR**. |
| 📊 **Reporting** | Exports results in **JSON**, **CSV**, and **futuristic animated HTML dashboards**. |
| 🔍 **Filtering** | Live search and filter by severity directly within the interactive report. |
| 🎨 **UI & UX** | Modern **glassy cyber-SOC interface** powered by **GSAP animations** and **Chart.js**. |

---

## 🧰 Installation

```bash
# Clone the repository
git clone https://github.com/Ni7H1N/LCS-Scanner
cd LCS-Scanner

# Create a virtual environment
python -m venv .venv
.venv\Scripts\activate       # Windows
# or
source .venv/bin/activate    # macOS / Linux

# Install dependencies
pip install -r requirements.txt

# Run your first scan:
python lcs_scanner.py --path ./samples --out ./reports --intel --ai --compliance multi --futuristic
