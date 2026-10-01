# Incident Write-up #001: Scheduled Task Persistence

**Date:** 2026-10-01
**Analyst:** Gonzalo Sebastián Vázquez
**Host:** win11-victim (192.168.56.103)
**Severity:** Medium (would be High if unauthorized: one task runs as SYSTEM at boot)
**Status:** Closed – True Positive (authorized adversary simulation, Atomic Red Team T1053.005-1)

## Summary
Two scheduled tasks were created on win11-victim within one second by a single command line launched from PowerShell. One runs at every user logon, the other at every system startup as SYSTEM. Both execute `cmd.exe /c calc.exe`. This matches the persistence technique T1053.005. Activity was confirmed as an authorized Atomic Red Team test, and the tasks were removed.

## Detection
Hunted for task creation through Sysmon process-creation events (Event ID 1):

    index=windows host=win11-victim EventCode=1 Image="*schtasks.exe"
    | table _time Image CommandLine ParentImage User

## Investigation

**Process chain (all times UTC):**

    powershell.exe (user: WIN11-VICTIM\analyst)
       └── cmd.exe                      16:27:23.711
             ├── schtasks.exe           16:27:24.301  /create /tn "T1053_005_OnLogon"   /sc onlogon
             └── schtasks.exe           16:27:25.129  /create /tn "T1053_005_OnStartup" /sc onstart /ru system

**Key observations:**
- A single `cmd.exe` command line chained both `schtasks /create` commands with `&`, which indicates scripted rather than manual activity.
- `T1053_005_OnStartup` runs as **SYSTEM**, the highest privilege level on Windows.
- The payload, `cmd.exe /c calc.exe`, is a benign stand-in typical of test frameworks. In a real attack this would point to malware.

**Corroborating evidence (Sysmon Event ID 11, file created):**

| Time (UTC) | Process | File | User |
|---|---|---|---|
| 16:27:24.421 | svchost.exe | C:\Windows\System32\Tasks\T1053_005_OnLogon | SYSTEM |
| 16:27:25.208 | svchost.exe | C:\Windows\System32\Tasks\T1053_005_OnStartup | SYSTEM |

The Task Scheduler service (hosted in svchost.exe) wrote each task definition about 0.1 s after the matching `schtasks` command. The events were linked by timing and task name.

    index=windows host=win11-victim "T1053_005"
    | stats count by source, EventCode

## Threat Intel
No external indicators were involved (no IPs, domains, or unknown files). All binaries are built-in Windows components (`cmd.exe`, `schtasks.exe`, `calc.exe`), so no VirusTotal lookup was needed. Abuse of legitimate system tools like this is common in real attacks ("living off the land").

## MITRE ATT&CK
- **T1053.005 – Scheduled Task/Job: Scheduled Task**
- Tactics: Persistence, Execution, Privilege Escalation (task configured to run as SYSTEM)

## Verdict & Recommendation
**True Positive, authorized test.** Activity matches Atomic Red Team test T1053.005-1 run by the analyst. Tasks removed with the framework's cleanup command. No escalation required.

If this activity were **unauthorized**, I would escalate to L2 immediately and recommend: isolating the host, deleting both tasks, identifying how PowerShell was launched (initial access), and checking other hosts for the same task names.

**Detection improvements identified:**
1. **Visibility gap:** no Security log Event ID 4698 (scheduled task created) was recorded, because this audit policy is disabled by default. Recommend enabling "Audit Other Object Access Events."
2. Create a Splunk alert for `schtasks.exe` with `/create` combined with `/ru system`, `onlogon`, or `onstart`.

## Evidence
Screenshots in [`/screenshots/day-04`](../screenshots/day-04/).
