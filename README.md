# Lab 01: Splunk Windows Log Analysis

## Lab Status

Completed

## Objective

The objective of this lab was to configure Splunk Enterprise to collect local Windows event logs and investigate authentication, privileged logon, and process creation activity from a SOC analyst perspective.

## Tools Used

- Splunk Enterprise
- Windows Security Event Logs
- Windows Event Viewer
- PowerShell
- GitHub

## Lab Environment

Splunk Enterprise was installed locally on a Windows computer. The following Windows Event Log channels were configured as Splunk data inputs:

- Security
- System
- Application

Personal account information was redacted from public screenshots.

## Investigation Scenario

A Windows endpoint was monitored using Splunk. The investigation focused on identifying normal authentication activity, generating a controlled failed-login event, reviewing privileged sessions, and examining newly created processes.

## Important Windows Event IDs

| Event ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4672 | Special privileges assigned to a new logon |
| 4688 | New process created |
| 5379 | Credential Manager credentials were read |

## Steps Performed

1. Installed and opened Splunk Enterprise.
2. Confirmed Splunk was indexing its internal logs.
3. Configured Security, System, and Application event log collection.
4. Confirmed that all three Windows log sources were entering Splunk.
5. Created a summary of Windows Security Event IDs.
6. Investigated successful Windows logons.
7. Created a temporary local lab account.
8. Generated one controlled failed interactive login.
9. Investigated and summarized the failed-login event.
10. Reviewed privileged logon activity.
11. Reviewed Windows process creation events.
12. Removed the temporary lab account.
13. Redacted personal information before uploading evidence.

## Splunk Searches

### Confirm Splunk Is Working

```spl
index=_internal
| head 20
```

### Confirm Windows Log Collection

```spl
index=* source="WinEventLog:*"
| stats count by source
| sort - count
```

### Security Event ID Summary

```spl
index=* source="WinEventLog:Security"
| stats count by EventCode
| sort - count
```

### Successful Interactive Logons

```spl
index=* source="WinEventLog:Security" EventCode=4624
(Logon_Type=2 OR Logon_Type=7 OR Logon_Type=10 OR Logon_Type=11)
| eval Target_Account=mvindex(Account_Name,-1)
| eval Target_Account=if(match(Target_Account,"@"),"[REDACTED USER ACCOUNT]",Target_Account)
| table _time, host, Target_Account, Logon_Type, Source_Network_Address
| sort - _time
```

### Failed Login Investigation

```spl
index=* source="WinEventLog:Security" EventCode=4625
| eval Failed_Account=mvindex(Account_Name,-1)
| table _time, host, Failed_Account, Failure_Reason, Logon_Type, Source_Network_Address
| sort - _time
```

### Failed Login Summary

```spl
index=* source="WinEventLog:Security" EventCode=4625
| eval Failed_Account=mvindex(Account_Name,-1)
| stats count, earliest(_time) as First_Attempt, latest(_time) as Last_Attempt by Failed_Account, host, Failure_Reason, Logon_Type
| convert ctime(First_Attempt) ctime(Last_Attempt)
| sort - count
```

### Privileged Logons

```spl
index=* source="WinEventLog:Security" EventCode=4672
| eval Privileged_Account=mvindex(Account_Name,-1)
| eval Privileged_Account=if(match(Privileged_Account,"@"),"[REDACTED USER ACCOUNT]",Privileged_Account)
| table _time, host, Privileged_Account, Privileges
| sort - _time
```

### Process Creation Events

```spl
index=* source="WinEventLog:Security" EventCode=4688
| eval Process_Account=mvindex(Account_Name,-1)
| eval Process_Account=if(Process_Account="hanse","[REDACTED USER]",Process_Account)
| table _time, host, Process_Account, New_Process_Name, Creator_Process_Name, Process_Command_Line
| sort - _time
```

## Findings

### Successful Logons

Successful Event ID 4624 activity included Logon Types 7 and 11. These represented local computer unlock and cached interactive authentication activity. The source address `127.0.0.1` indicated local activity.

### Failed Login

One controlled Event ID 4625 was generated using the temporary account `LabTestUser`.

The event showed:

- Failed account: `LabTestUser`
- Failure reason: Unknown username or bad password
- Logon Type: 2
- Source address: `127.0.0.1`
- Number of attempts: 1

This was expected lab activity and did not represent a real attack.

### Privileged Logons

Event ID 4672 activity was primarily associated with the Windows `SYSTEM` account. The visible activity appeared consistent with normal operating-system and service activity.

In a production environment, privileged logons involving unexpected accounts, unusual times, or suspicious processes would require further investigation.

### Process Creation

Event ID 4688 showed Windows and Splunk processes including:

- `RuntimeBroker.exe`
- `backgroundTaskHost.exe`
- `splunkd.exe`
- `splunk.exe`
- `cmd.exe`
- `postgres.exe`

The creator process information helped show what launched each process. No clearly suspicious process activity was identified in the reviewed events.

## MITRE ATT&CK Context

Repeated failed logins can be associated with:

- Tactic: Credential Access
- Technique: Brute Force
- Technique ID: T1110

The single controlled failed login generated in this lab was not classified as brute-force activity.

## Analyst Conclusion

Splunk successfully collected and searched local Windows Security, System, and Application logs.

The investigation demonstrated how a SOC analyst can use Windows Event IDs to examine authentication events, summarize failed logins, review privileged sessions, and investigate process execution.

The activity reviewed during this lab appeared consistent with expected Windows and controlled test activity. In a real investigation, I would correlate these events with usernames, source IP addresses, endpoint history, threat intelligence, process behavior, and activity on other systems before determining whether escalation was required.

## Screenshots

### Splunk Internal Events

![Splunk internal events](screenshots/01-splunk-internal-events.png)

### Windows Event Sources

![Windows event sources](screenshots/02-windows-event-sources.png)

### Security Event ID Summary

![Security Event ID summary](screenshots/03-security-eventcode-summary.png)

### Successful Login Investigation

![Successful login investigation](screenshots/04-successful-logins.png)

### Failed Login Investigation

![Failed login investigation](screenshots/05-failed-login-investigation.png)

### Failed Login Summary

![Failed login summary](screenshots/06-failed-login-summary.png)

### Privileged Logon Investigation

![Privileged logon investigation](screenshots/07-privileged-logons.png)

### Process Creation Investigation

![Process creation investigation](screenshots/08-process-creation-events.png)

## Skills Demonstrated

- Splunk Search Processing Language
- Windows Event Log collection
- Authentication analysis
- Failed-login investigation
- Privileged account monitoring
- Process creation analysis
- Security event correlation
- Evidence collection
- Data redaction
- SOC investigation documentation

## Resume Project Description

Analyzed Windows authentication, privileged logon, and process creation events using Splunk Enterprise. Investigated Event IDs 4624, 4625, 4672, and 4688, generated controlled security events, created analyst summaries, and documented findings in a public GitHub portfolio.
