# SOC SIEM Detection Lab

**Tools used:** Splunk Enterprise, Windows 11 (host), Atomic Red Team, PowerShell

**Objective:** Build a working SIEM pipeline, simulate real attack techniques, and detect them through log analysis and custom alerting.

## Attack 1: Brute Force Login Attempts (T1110)

**What I did:** Simulated repeated failed authentication attempts against the local machine using `net use` with incorrect credentials, mimicking a brute-force login attack.

**Detection:** Queried Windows Security Event Log for `EventCode=4625` (failed logon). Built a detection query grouping failures by account and host, flagging any account with more than 3 failed attempts within the search window.

**Evidence:** 11 failed logon events captured and confirmed in Splunk.

**MITRE ATT&CK Technique:** T1110 – Brute Force

**Verdict:** True positive (simulated)

**Response:** In a real environment — lock the account, block the source, escalate to Tier 2 for investigation.

**Alert built:** `Brute_Force_Detection_Alert` — real-time alert triggering when failed logon count exceeds threshold.

---

## Attack 2: PowerShell Encoded Command Execution (T1059.001)

**What I did:** Executed a base64-encoded PowerShell command (`-EncodedCommand`) — a technique commonly used by attackers to obfuscate malicious payloads and evade basic keyword-based detection.

**Detection:** Searched Windows Security Event Log for PowerShell-related activity. Found 21 related events referencing PowerShell module/DLL access, confirming PowerShell execution was recorded at the OS level.

**Limitation identified:** Full command-line visibility (Event ID 4688 process creation with command-line arguments, or Event ID 4104 script block logging) was not available, since Windows does not enable detailed command-line auditing or PowerShell script block logging by default — this requires explicit Group Policy / registry configuration that is outside the default audit policy.

**MITRE ATT&CK Technique:** T1059.001 – Command and Scripting Interpreter: PowerShell

**Verdict:** True positive (simulated), partial log visibility

**Response:** In a real environment — enable PowerShell Script Block Logging and Module Logging via GPO, enforce command-line process auditing (Event ID 4688), and alert on `-EncodedCommand` usage specifically, since it is a well-known evasion indicator.

---

## Key Takeaway

This lab reflects a common real-world SOC challenge — default Windows logging often has gaps, and part of the analyst's job is identifying and closing those visibility gaps through proper audit policy configuration.
