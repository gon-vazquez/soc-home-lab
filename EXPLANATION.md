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

## The L1 loop (what you're training for)

```
Alert → Triage → Investigate → Document → Close or Escalate
```
- **Alert:** something suspicious is flagged.
- **Triage:** quickly decide — real or not? How serious?
- **Investigate:** dig into the logs for evidence.
- **Document:** write it down (ticket / write-up).
- **Close or escalate:** harmless → close. Real and serious → send to L2.

So far you've practiced **Investigate** and **Document**. Next days add the rest.
