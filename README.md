# Password-Spraying-Detection
# Detecting Password Spraying with Splunk in a Windows AD Lab

## Environment
- **Attacker host:** Kali Linux
- **Target:** Windows Server 2022 Domain Controller (`DC01`, domain `lab.local`), running in VirtualBox
- **SIEM:** Splunk (Ubuntu), receiving Windows Security event logs via Universal Forwarder
- **Tooling:** CrackMapExec (SMB), `xfreerdp` (planned follow-on)

## Scenario
Simulate an external attacker performing a password spray against a set of domain accounts, then trace the resulting telemetry through Splunk to build a working detection — including validating what happens if the spray succeeds and the attacker attempts to use the compromised account further.

Password spraying (MITRE ATT&CK **T1110.003**) uses one or a small number of common passwords against *many* usernames, rather than many passwords against one account — this keeps each account's failed-attempt count under typical lockout thresholds while still finding weak credentials across a large user base.

## Attack Steps

**1. Reconnaissance**
```bash
nmap -p 445,3389 10.0.2.200
```
Confirmed SMB (445) open on the target.

**2. Password spray via CrackMapExec**
```bash
crackmapexec smb 10.0.2.200 -u rockyou.txt -p password.txt
```
`users.txt` contained 5 domain accounts (`Admin1`, `BigGen`, `NightMan`, `serv-app`, `Employee1`); `passwords.txt` contained 5 candidate passwords, keeping per-account attempts at or below a typical 3-attempt lockout policy.

One account (`Employee1`) was deliberately set to match a password in the list, to produce a realistic mixed result: several `STATUS_LOGON_FAILURE` responses and one successful authentication — rather than an all-fail run that doesn't reflect how a real spray plays out.

**3. Post-compromise validation (using the successful credential)**
```bash
crackmapexec smb 10.0.2.200 -u Employee1 -p 'correctpasword!' --shares
crackmapexec smb 10.0.2.200 -u Employee1 -p 'correctpassword!' --users
crackmapexec smb 10.0.2.200 -u Employee1 -p correctpassword!' -x "whoami"
```
Confirmed remote code execution against the target using the compromised account, and confirmed it was a domain account (`lab.local\Employee1`).

**4. Attempted privilege escalation**
```bash
crackmapexec smb 10.0.2.200 -u Employee1 -p 'correct password' -x "net group \"Domain Admins\" Employee1 /add /domain"
```
CrackMapExec returned a `[+]` (execution succeeded), but this only confirms the *remote command ran* — not that its own logic succeeded.

## Verifying the Escalation Attempt (Ground Truth, Not Tool Output)
Checked the actual AD object state rather than trusting the CLI output:
```powershell
Get-ADGroupMember -Identity "Domain Admins"
```
`Employee1` was **not** present — the escalation failed. This is expected: a standard domain account has no delegated rights to modify Domain Admins membership. The permission check happens at the Active Directory layer regardless of whether the request originates locally or remotely — the identity behind the request is what's evaluated, not the path it arrives by.

Cross-checked against Splunk:
```spl
index=* EventCode=4728 Account_Name=Employee1
```
No results — consistent with no actual membership change having occurred.

## Detection Logic (Splunk)

**Final working query:**
```spl
index=* EventCode=4625
| eval Account_Name=mvfilter(Account_Name!="-")
| bucket _time span=3m
| stats dc(Account_Name) as distinct_accounts, count as total_attempts by _time, Source_Network_Address

```

**Logic:** flags any single source IP generating failed logons against 5+ distinct accounts inside a 3-minute window — the defining shape of a spray (many accounts, one source) rather than a brute force (one account, many attempts).

## Gotchas Hit and Fixed
These were the real troubleshooting steps, not part of a tutorial:

1. **Noise account (`-`) inflating the count.** A blank/anonymous `Account_Name` value appeared in results from SMB protocol negotiation, not from an actual spray target. Filtered it out.
2. **`Account_Name` is a multivalue field on 4625 events.** The raw event contains two "Account Name" fields (the Subject, usually `-`, and the actual target account). A naive `Account_Name!="-"` filter excluded the *entire event* because one of its two values matched `-`. Fixed with `mvfilter(Account_Name!="-")` to strip only the unwanted value from within the field.
3. **Grouping by `Account_Name` in the `stats by` clause silently broke the count.** Including the account itself in the `by` clause splits results into one row per account, capping `dc(Account_Name)` at 1 per row. The account field must be left out of `by` for `dc()` to count *across* accounts correctly.
4. **CrackMapExec's `[+]` does not confirm command-level success.** It confirms the SMB session executed the command remotely — not that the command's own result (e.g. `net group ... /add`) succeeded. Verified against AD state directly (`Get-ADGroupMember`) and the audit log, rather than trusting the tool's exit indicator.
5. **Remote password change via `net user` did not take effect, even from a confirmed local-admin account.** Attempted `net user Employee1 NewPassword123! /domain` via CrackMapExec `-x`, using both the compromised standard account and a separate account confirmed to have local admin rights (flagged `Pwn3d!` by CrackMapExec). In both cases, the old password remained valid afterward and no corresponding 4723/4724 event appeared in Splunk. Root cause not fully isolated — candidates considered: domain password complexity/history policy silently rejecting the value, or output truncation in CrackMapExec's `-x` execution path obscuring the actual `net user` error text. Flagged as an open item rather than a resolved one.

## Response / Containment Steps
Standard actions once this alert fires in a live environment:
1. Force password reset (and/or disable) any account with a successful logon mixed into the failed attempts.
2. Block or isolate the source IP at the firewall/edge.
3. Check the compromised account for further activity: additional logons to other hosts, privilege changes (4728/4732), process execution (4688 if enabled).
4. Confirm whether privilege escalation succeeded using ground-truth checks (AD object state), not just log presence or tool output.
5. Escalate to IR if a privileged account was involved or if escalation succeeded.

## MITRE ATT&CK Mapping
| Technique | ID | Notes |
|---|---|---|
| Password Spraying | T1110.003 | Initial access attempt against multiple domain accounts |
| Valid Accounts | T1078 | Compromised `Employee1` credential used for further actions |
| Account Manipulation (attempted, failed) | T1098 | Attempted addition to Domain Admins; blocked by least-privilege controls |

## Outcome
The spray successfully compromised one low-privilege domain account. The attempted escalation to Domain Admins was correctly blocked by AD's built-in permission model, and this was independently verified through both the target's actual state and the absence of a corresponding audit event — demonstrating that a compromised account does not automatically equal full domain compromise, and that log evidence should be treated as authoritative over tool output.
