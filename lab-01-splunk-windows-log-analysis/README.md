# Lab 01: Splunk Windows Log Analysis

## Objective

The objective of this lab is to practice SOC analyst skills by reviewing Windows security logs and documenting suspicious authentication activity.

## Tools Used

* Splunk Enterprise
* Windows Event Viewer
* Windows Security Logs
* GitHub

## Security Events Reviewed

| Event ID | Meaning                     |
| -------- | --------------------------- |
| 4624     | Successful login            |
| 4625     | Failed login                |
| 4672     | Special privileges assigned |
| 4688     | Process creation            |

## Investigation Scenario

A Windows system generated authentication and security events. The goal of this lab is to review Windows logs, identify failed login activity, and explain why those events matter in a SOC environment.

## Steps Performed

1. Installed Splunk Enterprise.
2. Opened Windows Event Viewer.
3. Reviewed Windows Security logs.
4. Identified important Windows Event IDs.
5. Documented failed login activity.
6. Connected the activity to SOC analyst investigation concepts.
7. Added findings and screenshots to GitHub.

## SOC Analyst Notes

Failed login events may happen when a user types the wrong password. However, repeated failed logins can also indicate brute force activity, password spraying, unauthorized access attempts, or compromised credentials.

## MITRE ATT&CK Mapping

* Tactic: Credential Access
* Technique: Brute Force
* Technique ID: T1110

## Analyst Conclusion

This lab demonstrates how Windows authentication logs can support a SOC investigation. In a real environment, I would review the affected username, source IP address, hostname, login time, number of attempts, and whether similar activity occurred across other systems.

## Screenshots

Screenshots will be added after the lab is completed.

