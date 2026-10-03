# Incident Write-up #002: Defender Exclusion Added

**Date:** 2026-10-02

**Analyst:** Gonzalo Sebastián Vázquez

**Host:** win11-victim (192.168.56.103)

**Severity:** High

**Status:** Closed – True Positive (authorized test)

**Ticket:** #1

## Summary
A Microsoft Defender folder exclusion was added for `C:\Temp\FakeMalware3` via a PowerShell command, run by the local user `analyst`. Excluding a folder stops Defender from scanning it, a common step attackers take to hide malware. The activity was detected in real time by a custom Splunk alert, investigated, and confirmed as an authorized test.

## Detection
A custom real-time Splunk alert, "Defender Exclusion Added", fired on Defender Event ID 5007 (configuration change) involving Exclusions:

    index=windows host=win11-victim source="*Defender*" EventCode=5007
    | search "Exclusions"
    | table _time Computer EventCode

## Investigation

**What / When:** Exclusion added for `C:\Temp\FakeMalware3` at 2026-10-02 16:28:15 UTC.

**How / Who:** Pivoted from the Defender event (which only shows SYSTEM applied the change) to PowerShell script block logging (Event ID 4104), which captured the exact command and the real user:

    index=windows host=win11-victim (EventCode=1 OR source="*PowerShell*") "ExclusionPath"
    | table _time Image CommandLine User ParentImage

- **Command:** `Add-MpPreference -ExclusionPath "C:\Temp\FakeMalware3"`
- **User:** local account `analyst` (SID S-1-5-21-…-1001)

**Key lesson:** the Defender 5007 event showed the change applied as SYSTEM (S-1-5-18), which hides the real actor. The PowerShell 4104 log revealed the actual human user. One log said *what* changed; another said *who* did it. Correlating both is what makes the verdict reliable.

## Threat Intel
No external indicators (no file, IP, or domain). The technique abuses a built-in Windows tool (`Add-MpPreference`), so there was nothing to look up on VirusTotal. This is "living off the land", using legitimate tools for malicious ends.

## MITRE ATT&CK
- **T1562.001 – Impair Defenses: Disable or Modify Tools**
- Tactic: Defense Evasion

## Verdict & Recommendation
**True Positive, authorized test.** The command was run by the analyst as a controlled exercise. No malware was placed in the excluded folder.

If this were **unauthorized**, I would escalate to L2 and recommend: remove the exclusion (`Remove-MpPreference -ExclusionPath`), scan the folder, determine how the user account came to run it, and check whether any file was dropped there before the exclusion was added.

**Detection improvements identified:**
1. Keep the real-time alert on Defender 5007 exclusion changes (done).
2. Add a companion alert on PowerShell 4104 containing `Add-MpPreference`, to catch the command even if the Defender log is missed.

## Evidence
Screenshots in [`/screenshots/day-05`](../screenshots/day-05/).
