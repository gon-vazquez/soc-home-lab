# How My SOC Lab Works — Explained Simply

A short class for each day of the lab. Read one day at a time. Each day ends with a few questions — try to answer them yourself before opening the answers.

---

## The big picture (read this first)

Think of the lab as a **house with a security system**:

| In the lab | In the house |
|---|---|
| **win11-victim** (Windows VM) | The house being protected |
| **Sysmon** | Security cameras inside the house |
| **Splunk Forwarder** | The cable sending camera footage to the control room |
| **Splunk** (on the Ubuntu VM) | The control room: screens + recordings archive |
| **Atomic Red Team** | A fake burglar you hire to test the system |
| **You** | The guard watching the screens |

A **SOC** (Security Operations Center) is that control room in a real company. An **L1 analyst** is the first guard: you see something suspicious, check if it's real, write down what happened, and either close it or call your boss (**escalate to L2**).

That's the whole job. Everything below is just details of how each piece works.

---

## Day 1 — The control room (Splunk server)

**What we built:** an Ubuntu Linux server running Splunk.

**Key terms**
- **Virtual machine (VM):** a fake computer running inside your real one. VirtualBox runs them. If you break one, your real PC is fine.
- **SIEM:** a tool that collects logs from many machines and lets you search them. Splunk is a SIEM.
- **Log:** a written record of something that happened ("user X logged in at 10:02").
- **Index:** a folder inside Splunk where logs are stored. Ours is called `windows`.
- **Port 9997:** the "door" Splunk listens on to receive logs. Ports are like numbered doors on a computer.
- **IP address:** a computer's address on a network. Splunk lives at `192.168.56.101`.

**What went wrong (and the lesson)**
- Ubuntu only used half the disk (LVM default). → *Always check that settings are what you expect.*
- Splunk refused to run as root (the all-powerful admin). We gave it its own limited user. → This is **least privilege**: give every program only the power it needs, so if it gets hacked, the damage is small.

**Check yourself**
1. In one sentence, what is a SIEM?
2. Why is it bad to run programs as root?

<details><summary>Answers</summary>

1. A tool that collects logs from many machines into one place so you can search them and detect threats.
2. If the program gets hacked, the attacker gets full control of the machine. A limited user limits the damage.
</details>

---

## Day 2 — The house (Windows victim)

**What we built:** a Windows 11 VM — the computer we watch and attack.

**Key terms**
- **Endpoint:** any computer a person uses (laptop, PC). Most attacks happen on endpoints.
- **Two network adapters:**
  - **NAT** = internet access (to download things).
  - **Host-only** = a private network only your VMs and PC can see. Lab traffic stays here.
- **Snapshot:** a saved "save point" of a VM. If an attack breaks something, you go back in seconds.

**What went wrong (and the lesson)**
- The Windows 10 download was gone, so we switched to Windows 11. → *Things change; adapt instead of getting stuck.*

**Check yourself**
1. Why does the lab use a host-only network?
2. Why take a snapshot before running attacks?

<details><summary>Answers</summary>

1. To keep lab traffic private and separate from your real network.
2. So you can restore a clean machine instantly after the test.
</details>

---

## Day 3 — Cameras and cables (Sysmon + Forwarder)

**What we built:** Windows now records detailed activity and sends it to Splunk.

**Key terms**
- **Sysmon:** a free Microsoft tool that logs what happens on Windows in detail. The most important event:
  - **Event ID 1 = Process created** ("this program started"). It tells you *which* program, *who* ran it, its **command line** (exact instructions), and its **parent** (which program launched it).
- **Process:** a program that's running. Notepad open = a Notepad process.
- **Parent process:** the program that started another one. You opened Notepad from the desktop → parent is `explorer.exe`.
- **Universal Forwarder:** a small program on Windows that sends logs to Splunk.
- **`inputs.conf`:** the forwarder's list of *which* logs to send.
- **Add-on:** a Splunk plugin that splits raw logs into clean **fields** (like `Image`, `User`, `CommandLine`) so you can search them easily.

**What went wrong (and the lesson)**
- Security logs arrived, but Sysmon logs didn't. We compared log **sources** in Splunk, found the gap, and discovered the forwarder's account wasn't allowed to read Sysmon's log. Fixed by adding it to **Event Log Readers**.
- → *When data is missing, compare what arrives vs. what should arrive. The gap points to the problem.*

**Your first detection**
```
index=windows EventCode=1 Image="*notepad.exe"
```
In plain words: *"In the windows folder, show me every time Notepad was started."*

**Check yourself**
1. What does Sysmon Event ID 1 record?
2. If `ParentImage` is `explorer.exe`, what does that tell you?
3. Why did Sysmon data go missing?

<details><summary>Answers</summary>

1. A program starting (process creation).
2. The program was launched by a user from the desktop / file explorer.
3. The forwarder's account didn't have permission to read the Sysmon log.
</details>

---

## Day 4 — The fake burglar (Attack + Investigation)

**What we did:** ran a real attacker technique, then found it in Splunk and wrote a report.

**Key terms**
- **Atomic Red Team:** a library of small, harmless versions of real attacks. Used to test if your detection works.
- **MITRE ATT&CK:** a public encyclopedia of attacker techniques, each with an ID. Analysts use it as a shared language.
  - **T1053.005 = Scheduled Task.**
- **Persistence:** how attackers make sure their malware comes back after a reboot. A **scheduled task** that runs "at every startup" is a classic way.
- **Process tree:** the chain of who-started-who. Ours: `powershell.exe → cmd.exe → schtasks.exe`.
- **Corroborating evidence:** a second, independent proof of the same thing. We saw the process (Event ID 1) *and* the task file being created on disk (Event ID 11).
- **True positive:** the alert is real. **False positive:** the alert fired, but it's harmless.
- **Write-up:** your report — what happened, evidence, verdict, what to do next.

**What we found**
- Two scheduled tasks created in under a second (= scripted, not a human clicking).
- One ran as **SYSTEM** (highest power on Windows) → more dangerous.
- **Visibility gap:** Windows can log task creation itself (Event ID 4698), but that setting was off. Noticing what you *can't* see is part of the job.

**Lessons**
- *Search around the incident time, not "the last 15 minutes"* — our evidence "disappeared" once the window moved.
- *Verify, don't assume:* we confirmed cleanup with `schtasks /query`.
- *Bonus find:* Defender logged our folder **exclusion** (Event ID 5007) — attackers do this too, to hide malware (**T1562.001**). That's write-up #002.

**Check yourself**
1. What is persistence, and why do attackers want it?
2. What's the difference between a true positive and a false positive?
3. Why was the startup task more dangerous than the logon task?
4. Why is a Defender exclusion suspicious in a real company?

<details><summary>Answers</summary>

1. A way to survive reboots so the attacker keeps access.
2. True positive = real threat. False positive = alert fired on harmless activity.
3. It runs as SYSTEM, with full control of the machine.
4. It tells the antivirus to stop scanning a folder — a perfect hiding place for malware.
</details>

---

## Day 5 — The full loop (one real case, start to finish)

**What we did:** took one suspicious event all the way through the job an L1 analyst actually does.

**The loop (memorize this):**

    Alert → Triage → Investigate → Document → Close or Escalate

**Key terms**
- **Alert:** a saved search that runs automatically and flags something suspicious, so you don't hunt by hand.
- **Scheduled vs real-time alert:** scheduled runs every X minutes; real-time fires the moment a matching event arrives. Real-time is instant but heavier on the server.
- **Triage:** the fast first look. Real or noise? How urgent? You size it up, you don't deep-dive yet.
- **Investigate:** the deep dive. Answer who, what, when, how, using the logs as proof.
- **SID (Security Identifier):** Windows' internal ID for an account. `S-1-5-18` = SYSTEM (not a person). `S-1-5-21-...-1001` = a real local user.
- **Pivoting:** jumping from one log to another to answer a new question. The Defender log said *what* changed; the PowerShell log said *who* ran it.
- **Ticket:** the short record of an incident (we used a GitHub Issue). **Write-up:** the full report it links to.
- **True Positive / False Positive:** real threat vs. harmless activity that tripped the alert.
- **Escalate:** hand a real, serious incident to L2.

---

### My first finished L1 loop (worked example)

**Alert**

We set up an alert with the following command:

    index=windows host=win11-victim source="*Defender*" EventCode=5007
    | search "Exclusions"
    | table _time Computer EventCode

It triggers every 1 hour, but I manually ran it once in real-time mode. The severity of the alert is high because it represents a T1562.001 (Impair Defenses: Disable or Modify Tools) attack, according to the MITRE ATT&CK framework.

I read and understood the attack before creating an alert that automatically detects it without me having to dig into thousands of logs to find that specific attack. That's why the first step is to UNDERSTAND an attack, then set up an alert that actively searches for it, and then proceed with Triage.

**Triage**

The next step is Triage, which basically means to quickly decide whether the log is real or not and how urgent it is.

1. Detection: Direct change to Defender's config (Event ID 5007). Severity: High, because it could mean an attacker just added a Defender exclusion to hide their malware in a specific folder.
2. Is it plausibly real? Yes, this is suspicious and needs investigation to rule out legitimate activity (e.g. an IT admin could have excluded the folder for performance).
3. Verdict: High severity and plausibly malicious, so investigate immediately, but the actual impact is still unknown.

**Investigation**

In cybersecurity, you should never assume something's safe or at risk without diving deeper into the logs. Zero trust means to never trust something by default. Furthermore, corroborating evidence is a good practice that any great L1 analyst should do to confirm whether an event is a real cyberattack or not. So Investigation turns into the immediate next step: digging into the logs. It revolves around three questions: who did it? when did it happen? what exactly happened (e.g. command, excluded path, etc)?

1. EXCLUDED: C:\Temp\FakeMalware3
2. ACTOR: S-1-5-21-73524690-744499101-3220969325-1001 (resolved to the local user `analyst`)
3. COMMAND: Add-MpPreference -ExclusionPath "C:\Temp\FakeMalware3"
4. TIMESTAMP: 2026-10-02T16:28:15 UTC

Found via PowerShell script block logging (Event ID 4104), after the Defender 5007 event only showed SYSTEM. One log said *what* changed; another said *who* did it.

**Documentation**

Two records: a **ticket** and a **write-up**.
- Ticket: GitHub Issue #1, `[HIGH] Defender exclusion added on win11-victim`, with labels `severity: high` and `status: investigating`. This mimics a real SOC ticketing system (like ServiceNow or Jira).
- Write-up: `writeups/002-defender-exclusion.md`, the full report, linked from the ticket.

**Close or Escalate**

Verdict: **True Positive, but authorized** (I ran the command myself as a test), so the ticket is closed, no escalation. In a real SOC, an *unauthorized* exclusion would be escalated to L2 instead. Closed the ticket with a verdict comment and changed its label to `status: closed – true positive`.

---

**The lessons that matter**
- *Understand the attack first, then build the alert.* You can't detect what you don't understand.
- *Suspicious ≠ confirmed.* A Defender exclusion has legitimate uses. Triage says "investigate," not "we're breached."
- *Stay objective.* Don't write the story ahead of the evidence.
- *One log rarely tells the whole story.* Correlation is the skill.
- *Noisy changes make noisy alerts.* Removing exclusions also fired the alert, real alerts should focus on the suspicious direction (additions), not cleanup.

**Check yourself**
1. What are the five stages of the L1 loop, in order?
2. Why wasn't the Defender 5007 event enough to identify who did it?
3. What's the difference between triage and investigation?
4. Give one legitimate reason someone adds a Defender exclusion.

<details><summary>Answers</summary>

1. Alert → Triage → Investigate → Document → Close or Escalate.
2. It showed the change applied as SYSTEM (S-1-5-18), which hides the real user. PowerShell logging (4104) revealed the actual account.
3. Triage is the fast "is this real and how urgent?" check. Investigation is the deep dive for evidence (who/what/when/how).
4. Performance, IT excludes large/trusted folders (databases, backups, build directories) so Defender doesn't slow them down.
</details>

---

## The L1 loop (what I'm training for)

```
Alert → Triage → Investigate → Document → Close or Escalate
```
- **Alert:** something suspicious is flagged.
- **Triage:** quickly decide — real or not? How serious?
- **Investigate:** dig into the logs for evidence.
- **Document:** write it down (ticket / write-up).
- **Close or escalate:** harmless → close. Real and serious → send to L2.

So far you've practiced **Investigate** and **Document**. Next days add the rest.
