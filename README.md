# SOC Analyst Lab Portfolio

## Overview

This repository documents hands-on cybersecurity projects focused on the practical skills required for entry-level Security Operations Center (SOC) and Cybersecurity Analyst roles.

The portfolio includes security monitoring, Windows event analysis, phishing investigation, scripting, SIEM triage, vulnerability management, MITRE ATT&CK mapping, and incident response documentation.

## Career Goal

I am a cybersecurity new graduate building practical experience for roles such as:

- SOC Analyst I
- Junior Cybersecurity Analyst
- Security Operations Analyst
- Cyber Defense Analyst
- Information Security Analyst

My goal is to demonstrate that I can investigate security activity, document findings, communicate risk, and use common SOC tools and techniques.

## Technical Skills

- Splunk Enterprise
- Microsoft Sentinel
- Windows Security Event Logs
- Security alert triage
- Phishing email analysis
- PowerShell
- Python
- Kusto Query Language (KQL)
- MITRE ATT&CK
- Vulnerability management
- Incident response
- IOC documentation
- GitHub technical documentation

## Labs

| Lab | Topic | Status |
|---|---|---|
| [Lab 01](lab-01-splunk-windows-log-analysis/README.md) | Splunk Windows Log Analysis | **Completed** |
| [Lab 02](lab-02-phishing-email-investigation/README.md) | Phishing Email Investigation | **Completed** |
| [Lab 03](lab-03-powershell-security-automation/README.md) | PowerShell Security Automation | **Completed** |
| [Lab 04](lab-04-python-alert-triage-automation/README.md) | Python Alert Triage Automation | **Completed** |
| [Lab 05](lab-05-vulnerability-management-report/README.md) | Vulnerability Management Report | **Completed** |
| Lab 06 | HIPAA Security Incident Response Case Study | Planned |
| Lab 07 | Microsoft Sentinel Incident Triage | Planned |

---

## Lab 01: Splunk Windows Log Analysis

Configured Splunk Enterprise to collect local Windows Security, System, and Application event logs.

The investigation included:

- Validating Windows log ingestion
- Reviewing Event ID 4624 successful logons
- Generating and investigating a controlled Event ID 4625 failed logon
- Reviewing Event ID 4672 privileged logons
- Reviewing Event ID 4688 process creation
- Creating SPL searches and analyst summaries
- Redacting personal information before publishing evidence

**Skills demonstrated:** Splunk SPL, Windows event analysis, authentication investigation, privileged-account monitoring, process analysis, evidence collection, and SOC documentation.

[View Lab 01](lab-01-splunk-windows-log-analysis/README.md)

---

## Lab 02: Phishing Email Investigation

Investigating a simulated phishing email by reviewing:

- Sender and reply-to addresses
- Email headers
- SPF, DKIM, and DMARC results
- Lookalike domains
- Suspicious URLs
- Social-engineering techniques
- Indicators of compromise
- Containment and response recommendations

**Skills demonstrated:** phishing analysis, header analysis, IOC documentation, MITRE ATT&CK mapping, and incident-response recommendations.

[View Lab 02](lab-02-phishing-email-investigation/README.md)

---

## Planned Labs

### Lab 03: PowerShell Security Automation

Create a PowerShell script that reviews Windows security events, identifies suspicious authentication activity, and exports analyst-ready results.

### Lab 04: Python Alert Triage Automation

Build a Python tool that reads security alerts, assigns risk levels, prioritizes suspicious activity, and produces a structured triage report.

### Lab 05: Microsoft Sentinel Incident Triage

Use Microsoft Sentinel and KQL to investigate a simulated security incident, review entities, build a timeline, and document containment recommendations.

### Lab 06: Vulnerability Management Report

Analyze vulnerability findings, prioritize remediation using severity and business impact, and create technical and executive-level recommendations.

### Lab 07: HIPAA Security Incident Response Case Study

Develop a healthcare-focused incident-response case study covering investigation, containment, evidence preservation, communication, and lessons learned.

---

## Portfolio Structure

```text
soc-analyst-lab-portfolio/
├── README.md
├── lab-01-splunk-windows-log-analysis/
│   ├── README.md
│   └── screenshots/
├── lab-02-phishing-email-investigation/
│   ├── README.md
│   ├── lab-02-simulated-phishing-email.eml
│   └── screenshots/
├── lab-03-powershell-security-automation/
├── lab-04-python-alert-triage-automation/
├── lab-05-microsoft-sentinel-incident-triage/
├── lab-06-vulnerability-management-report/
└── lab-07-hipaa-security-incident-response-case-study/
```

## Documentation Standards

Each completed lab will include:

- A realistic security scenario
- Tools and technologies used
- Step-by-step investigation notes
- Searches, commands, or code
- Screenshots and supporting evidence
- Findings and analyst conclusions
- MITRE ATT&CK mapping where relevant
- Containment or remediation recommendations
- A resume-ready project description

## About Me

I am a Drexel University graduate with a background in Computing and Security Technology. I am developing hands-on experience in security monitoring, incident triage, Windows and network security, cloud security, data analysis, scripting, and SOC operations.

## Disclaimer

All suspicious activity, accounts, domains, IP addresses, and security events used in this portfolio are simulated, controlled, or safely generated for educational purposes. No real malicious activity was performed.

